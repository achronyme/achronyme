//! Union-Find clustering of the linear constraint set + the
//! per-cluster reduced row-echelon Gaussian solver. Split out of the
//! `optimize_linear_clustered` driver; the algorithms and their
//! ordering guarantees are documented per function.

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::{FieldBackend, FieldElement};

use super::parallel::linear_signal_entries_ordered;
use super::picker::{solve_for_variable_with_picker, Picker};
use crate::r1cs::{Constraint, LinearCombination, Variable};
use crate::r1cs_optimize::predicates::{is_linear, VarFreq};
use crate::r1cs_optimize::substitution::{apply_single_substitution_in_place, InvCache};
use crate::r1cs_optimize::types::SubstitutionMap;
use crate::r1cs_optimize::union_find::UnionFind;

/// Cluster the linear constraints in `linear_constraints` by shared
/// variable index. Two constraints land in the same cluster iff they
/// reference at least one common non-protected, non-`Variable::ONE`
/// signal.
///
/// Returns clusters as a `Vec<Vec<usize>>` of indices into
/// `linear_constraints`. Each cluster vec is sorted ascending; clusters
/// as a whole are sorted by their smallest member, so the output is
/// deterministic across runs.
///
/// **Skip rules:**
/// - `Variable::ONE` (index 0) is always skipped. Sharing the
///   constant wire would merge every constraint into one giant
///   cluster regardless of structure.
/// - Indices in `protected` (public inputs, decompose aux wires) are
///   also skipped. Clustering on a protected signal cannot enable a
///   substitution -- the picker will refuse to substitute it -- so
///   merging through it only inflates clusters without enabling work.
///
/// Constraints not classified as linear by `is_linear` produce
/// singleton clusters (they cannot contribute to or be reduced by
/// the Gauss step).
pub(in crate::r1cs_optimize) fn build_clusters_by_signal<F: FieldBackend>(
    linear_constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
) -> Vec<Vec<usize>> {
    let n = linear_constraints.len();
    let mut uf = UnionFind::new(n);

    // For each signal index, remember the first constraint that owns
    // it; subsequent owners union with that first. Signal extraction
    // may run in parallel, but this merge stays in original constraint
    // index order so Union-Find shape and output order are fixed.
    let mut first_owner: FxHashMap<usize, usize> = FxHashMap::default();
    for (idx, signals) in linear_signal_entries_ordered(linear_constraints, protected) {
        for sig in signals {
            match first_owner.get(&sig) {
                Some(&owner) => uf.union(idx, owner),
                None => {
                    first_owner.insert(sig, idx);
                }
            }
        }
    }

    // Bucket by root. Pushing in 0..n order keeps each cluster vec
    // sorted ascending.
    let mut by_root: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for idx in 0..n {
        let root = uf.find(idx);
        by_root.entry(root).or_default().push(idx);
    }
    let mut clusters: Vec<Vec<usize>> = by_root.into_values().collect();
    clusters.sort_by_key(|c| c[0]);
    clusters
}

/// Run reduced row-echelon Gaussian elimination on a single cluster of
/// linear constraints.
///
/// Each linear constraint `k * other = c_lc` is rewritten as the LC
/// `c_lc - k*other` that must equal zero. We pick a pivot row + a
/// pivot variable via `solve_for_variable` (max-frequency picker;
/// the size-conditional swap to min-occurrence happens in
/// `optimize_linear_clustered`), record the substitution
/// `var -> expr`, apply it to the remaining rows + previously-
/// recorded substitutions (composition), and repeat until no row
/// admits a substitution.
///
/// Inputs:
/// - `cluster_constraints`: linear constraints in this cluster.
///   Non-linear constraints (those for which `is_linear` returns
///   `None`) flow straight to the residual list -- they cannot
///   contribute to or be reduced by the linear Gauss step.
/// - `protected`: variables the picker must never substitute (public
///   inputs, `Variable::ONE`, decompose aux wires).
/// - `var_freq`: per-variable frequency over the full constraint
///   set, used by the max-frequency picker. The frequency map is
///   passed in (rather than computed locally over the cluster) so
///   the Gauss path matches the greedy path's heuristic exactly.
///
/// Output:
/// - `(SubstitutionMap, residual)`: the discovered substitutions
///   (composed acyclically -- each value LC references only
///   variables not in the substitution map's keys), plus any
///   constraints that could not be reduced (all-protected variables,
///   or non-linear constraints in the cluster). Residual constraints
///   are emitted in `1 * lc = 0` form mirroring the dense path.
pub(in crate::r1cs_optimize) fn solve_cluster_linear<F: FieldBackend>(
    cluster_constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
    var_freq: &VarFreq,
    inv_cache: &mut InvCache<F>,
) -> (SubstitutionMap<F>, Vec<Constraint<F>>) {
    let cluster_size = cluster_constraints.len();
    let picker = Picker::for_cluster_size(cluster_size);

    // Linearize: build the per-constraint "must equal zero" LC. The
    // rows are borrowed — the combined LCs are fresh allocations either
    // way, and the caller decides whether the originals survive (they
    // are needed verbatim when the whole round solves nothing).
    let mut zero_lcs: Vec<LinearCombination<F>> = Vec::new();
    let mut residual: Vec<Constraint<F>> = Vec::new();

    for c in cluster_constraints {
        match is_linear(c) {
            Some((k, other, c_lc)) => {
                // Constraint encodes k * other = c_lc, i.e.
                // c_lc - k*other = 0.
                let combined = (c_lc - (other * k)).simplify();
                zero_lcs.push(combined);
            }
            None => residual.push(c.clone()),
        }
    }

    let mut subs: SubstitutionMap<F> = FxHashMap::default();
    let mut local_protected = HashSet::new();

    loop {
        // Find the first row that admits a substitution.
        let mut found: Option<(usize, Variable, LinearCombination<F>)> = None;
        for (i, lc) in zero_lcs.iter().enumerate() {
            if let Some((var, expr)) = solve_for_variable_with_picker(
                lc,
                protected,
                &local_protected,
                var_freq,
                picker,
                inv_cache,
            ) {
                found = Some((i, var, expr));
                break;
            }
        }

        let Some((row_idx, var, expr)) = found else {
            break;
        };
        zero_lcs.swap_remove(row_idx);
        local_protected.insert(var.index());

        // Apply the new substitution to rows/substitutions that reference
        // the pivot and compose it into previously-recorded substitutions
        // so the final map is acyclic.
        let var_idx = var.index();
        for lc in zero_lcs.iter_mut() {
            apply_single_substitution_in_place(lc, var_idx, &expr);
        }
        for prev_expr in subs.values_mut() {
            apply_single_substitution_in_place(prev_expr, var_idx, &expr);
        }
        subs.insert(var_idx, expr);
        if zero_lcs.is_empty() {
            break;
        }
    }

    // Convert any remaining non-empty rows back to constraint form
    // (`1 * lc = 0`) so the caller can keep them in the system.
    // Empty rows are tautologies after substitution; skip them.
    for lc in zero_lcs {
        if !lc.terms().is_empty() {
            residual.push(Constraint {
                a: LinearCombination::from_constant(FieldElement::one()),
                b: lc,
                c: LinearCombination::zero(),
            });
        }
    }

    (subs, residual)
}
