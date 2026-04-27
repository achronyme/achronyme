//! O2 sparse pass -- DEDUCE on connected-component clusters with
//! `BTreeMap`-row Gaussian elimination.
//!
//! Mirror of `deduce::optimize_o2` for circuits where the dense
//! `k x q` monomial matrix would not fit in RAM (e.g. SHA-256, Keccak,
//! and other bit-heavy circuits where monomials and constraints both
//! reach 60k+).
//!
//! Algorithm:
//!
//! 1. O1 fixpoint (`optimize_linear`) -- shared with the dense path.
//! 2. Decompose multi-term A/B into auxiliary wires -- shared with the
//!    dense path (`deduce::decompose_for_deduce_tracked`).
//! 3. Sparse DEDUCE: expand each constraint into a (monomial map,
//!    linear residual) pair, Union-Find by shared monomial, then
//!    reduced row-echelon Gaussian elimination on each connected
//!    component using `BTreeMap`-row representation. Components above
//!    `MAX_CLUSTER_SIZE` are skipped (their quadratic constraints stay
//!    in the system unchanged) -- full-rank reduction without
//!    Markowitz pivoting / fill-in management is out of scope.
//! 4. Add deduced constraints; re-run O1 (with aux wires protected,
//!    then a cleanup O1 that eliminates them) -- shared with the dense
//!    path.
//! 5. Repeat steps 2-4 to convergence (bounded by 50 outer iterations).
//!
//! `optimize_o2_sparse` shares the entire outer loop with the dense
//! path through `deduce::optimize_o2_with_deducer`; only the inner
//! DEDUCE routine is swapped.

use std::collections::{BTreeMap, HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use super::deduce::{expand_constraint_product, optimize_o2_with_deducer, Monomial};
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use super::union_find::UnionFind;
use crate::r1cs::{Constraint, LinearCombination};

/// Largest cluster (in number of constraints) we run full Gaussian
/// elimination on. Beyond this, the cluster is skipped: full-rank
/// reduction without pivot-ordering heuristics costs
/// O(k_c^2 . density) and the per-iteration cost dominates without
/// Markowitz-style fill-in management.
///
/// 350 mirrors circom's published threshold; clusters of that size or
/// smaller solve in milliseconds while the marginal win on larger ones
/// is overshadowed by added wall-clock per outer iteration.
const MAX_CLUSTER_SIZE: usize = 350;

/// Sparse row representation: column index -> non-zero coefficient.
///
/// `BTreeMap` (rather than `HashMap`) gives deterministic iteration
/// order which makes cross-run reproducibility cheap to enforce.
type SparseRow<F> = BTreeMap<usize, FieldElement<F>>;

/// Per-constraint expansion: the quadratic monomial coefficients +
/// the linear residual `(A x B linear terms) - C`. Shared input shape
/// for clustering and per-cluster solving.
type ExpandedConstraint<F> = (HashMap<Monomial, FieldElement<F>>, LinearCombination<F>);

/// Cluster constraints by shared quadratic monomials.
///
/// Two constraints land in the same cluster iff there exists at least
/// one quadratic monomial appearing in both. Transitivity is enforced
/// through the Union-Find merge.
///
/// Returns clusters as a `Vec<Vec<usize>>` of original constraint
/// indices. Each cluster is sorted ascending; clusters as a whole are
/// sorted by their smallest member, so the output is deterministic
/// across runs (independent of `HashMap` iteration order).
fn cluster_constraints_by_monomial<F: FieldBackend>(
    expanded: &[ExpandedConstraint<F>],
) -> Vec<Vec<usize>> {
    let n = expanded.len();
    let mut uf = UnionFind::new(n);

    // Map each monomial to the first constraint index that contained
    // it; subsequent constraints with the same monomial union with
    // that owner. Iterating `quad.keys()` is `HashMap`-ordered (i.e.
    // non-deterministic) but the equivalence-class structure produced
    // by Union-Find is identical regardless of merge order.
    let mut first_owner: HashMap<Monomial, usize> = HashMap::new();
    for (idx, (quad, _)) in expanded.iter().enumerate() {
        for &mono in quad.keys() {
            match first_owner.get(&mono) {
                Some(&owner) => uf.union(idx, owner),
                None => {
                    first_owner.insert(mono, idx);
                }
            }
        }
    }

    // Bucket by root. Pushing in 0..n order means each cluster vec is
    // already sorted ascending.
    let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for idx in 0..n {
        let root = uf.find(idx);
        by_root.entry(root).or_default().push(idx);
    }
    let mut clusters: Vec<Vec<usize>> = by_root.into_values().collect();
    // Sort across clusters so the deduction order is reproducible
    // across runs (the root index depends on union order).
    clusters.sort_by_key(|c| c[0]);
    clusters
}

/// Run full reduced row-echelon Gaussian elimination on a single cluster.
///
/// `cluster` lists original constraint indices. `expanded[i]` is the
/// monomial map + linear residual for constraint `i`.
///
/// Returns one `LinearCombination` per deduction; each represents
/// `lc = 0` and arises from a non-pivot row whose quadratic part
/// vanished during reduction.
fn solve_cluster_sparse<F: FieldBackend>(
    cluster: &[usize],
    expanded: &[ExpandedConstraint<F>],
) -> Vec<LinearCombination<F>> {
    if cluster.is_empty() {
        return vec![];
    }

    // Assign deterministic column indices to monomials in this cluster.
    let mut monos: Vec<Monomial> = Vec::new();
    {
        let mut seen: HashSet<Monomial> = HashSet::new();
        for &ci in cluster {
            for &m in expanded[ci].0.keys() {
                if seen.insert(m) {
                    monos.push(m);
                }
            }
        }
    }
    monos.sort();
    let mono_idx: HashMap<Monomial, usize> =
        monos.iter().enumerate().map(|(i, &m)| (m, i)).collect();
    let q = monos.len();

    if q == 0 {
        // Singleton cluster of a purely-linear constraint -- no quadratic
        // monomials to reduce, no deduction available.
        return vec![];
    }

    // Build sparse rows + linear parts in cluster order.
    let k = cluster.len();
    let mut rows: Vec<SparseRow<F>> = Vec::with_capacity(k);
    let mut linear_parts: Vec<LinearCombination<F>> = Vec::with_capacity(k);
    for &ci in cluster {
        let (quad, lin) = &expanded[ci];
        let mut row: SparseRow<F> = BTreeMap::new();
        for (&m, &coeff) in quad {
            row.insert(mono_idx[&m], coeff);
        }
        rows.push(row);
        linear_parts.push(lin.clone());
    }

    // Column-major reduced row-echelon: walk columns in monomial-tuple
    // order, find first non-pivoted row with a non-zero entry there,
    // normalize it, and clear that column in every other row.
    let mut used_as_pivot: Vec<bool> = vec![false; k];

    for col in 0..q {
        let pivot_row = (0..k).find(|&r| !used_as_pivot[r] && rows[r].contains_key(&col));
        let Some(pr) = pivot_row else {
            continue;
        };
        used_as_pivot[pr] = true;

        // Normalize pivot row so the pivot entry becomes 1.
        let pivot_val = *rows[pr]
            .get(&col)
            .expect("pivot known to be present (filtered by contains_key)");
        let pivot_inv = match pivot_val.inv() {
            Some(inv) => inv,
            // Unreachable on a prime field with non-zero pivot, but
            // mirror the dense path's defensive `continue`.
            None => continue,
        };
        for v in rows[pr].values_mut() {
            *v = v.mul(&pivot_inv);
        }
        linear_parts[pr] = linear_parts[pr].clone() * pivot_inv;

        // Eliminate this column from every other row that has it.
        // Snapshot the pivot row's entries up front to side-step the
        // simultaneous mutable borrow on `rows`.
        let pivot_entries: Vec<(usize, FieldElement<F>)> =
            rows[pr].iter().map(|(&c, &v)| (c, v)).collect();
        let pivot_lin = linear_parts[pr].clone();

        for r in 0..k {
            if r == pr {
                continue;
            }
            let factor = match rows[r].get(&col) {
                Some(&f) if !f.is_zero() => f,
                _ => continue,
            };
            let neg_factor = factor.neg();
            for &(pc, pv) in &pivot_entries {
                let delta = pv.mul(&neg_factor);
                let entry = rows[r].entry(pc).or_insert_with(FieldElement::<F>::zero);
                *entry = entry.add(&delta);
                if entry.is_zero() {
                    rows[r].remove(&pc);
                }
            }
            let scaled = pivot_lin.clone() * neg_factor;
            linear_parts[r] = (linear_parts[r].clone() + scaled).simplify();
        }
    }

    // Non-pivot rows whose quadratic part vanished are deductions.
    let mut deduced: Vec<LinearCombination<F>> = Vec::new();
    for r in 0..k {
        if used_as_pivot[r] {
            continue;
        }
        if !rows[r].is_empty() {
            continue;
        }
        let lin = linear_parts[r].simplify();
        if !lin.terms.is_empty() {
            deduced.push(lin);
        }
    }
    deduced
}

/// Deduce linear constraints from quadratic ones using sparse rows
/// over connected-component clusters.
///
/// Returns one `LinearCombination` per deduction; each is interpreted
/// as `lc = 0`.
pub(super) fn deduce_linear_from_quadratic_sparse<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> Vec<LinearCombination<F>> {
    if constraints.is_empty() {
        return vec![];
    }

    let expanded: Vec<_> = constraints.iter().map(expand_constraint_product).collect();

    let clusters = cluster_constraints_by_monomial(&expanded);

    let mut deduced: Vec<LinearCombination<F>> = Vec::new();
    for cluster in &clusters {
        if cluster.len() > MAX_CLUSTER_SIZE {
            continue;
        }
        deduced.extend(solve_cluster_sparse(cluster, &expanded));
    }
    deduced
}

/// Sparse-clustered O2 optimization. Same outer-loop structure as the
/// dense `optimize_o2`; differs only in the DEDUCE inner step.
pub fn optimize_o2_sparse<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_o2_with_deducer(
        constraints,
        num_pub_inputs,
        deduce_linear_from_quadratic_sparse,
    )
}

/// Diagnostic: returns the size of each monomial-shared cluster that
/// `deduce_linear_from_quadratic_sparse` would build for the given
/// constraints (without solving any of them). Sizes are returned
/// in cluster-iteration order (sorted by smallest member index).
///
/// Intended only for instrumentation/research (e.g. measuring how
/// many constraints sit in clusters above `MAX_CLUSTER_SIZE`).
/// Not part of the core optimizer pipeline.
#[doc(hidden)]
#[allow(dead_code)]
pub fn diagnostic_monomial_cluster_sizes<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> Vec<usize> {
    if constraints.is_empty() {
        return vec![];
    }
    let expanded: Vec<_> = constraints.iter().map(expand_constraint_product).collect();
    let clusters = cluster_constraints_by_monomial(&expanded);
    clusters.iter().map(|c| c.len()).collect()
}

/// Diagnostic: returns the current `MAX_CLUSTER_SIZE` threshold at
/// which `deduce_linear_from_quadratic_sparse` stops attempting
/// Gaussian elimination on a monomial cluster.
#[doc(hidden)]
#[allow(dead_code)]
pub fn diagnostic_max_cluster_size() -> usize {
    MAX_CLUSTER_SIZE
}
