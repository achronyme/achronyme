//! Cluster-based Gaussian elimination on linear R1CS constraints.
//!
//! Mirrors circom 2.2.x's `linear_simplification` pipeline
//! (`constraint_list/src/constraint_simplification.rs:275` in
//! `iden3/circom`):
//!
//! 1. Partition the linear constraints into connected components via
//!    Union-Find on shared variable indices (one signal -> all
//!    constraints referencing it merge).
//! 2. Run reduced row-echelon Gaussian elimination over each cluster
//!    independently. Cluster sizes >= 350 use a min-occurrence
//!    picker; smaller clusters use the max-frequency picker.
//!
//! `optimize_linear_clustered` is the public entry; an
//! `_with_protected` variant exists for the same reason as in
//! `linear.rs:52` -- O2's outer loop calls it after
//! `decompose_for_deduce_tracked` to shield aux wires.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use super::linear::{deduplicate_constraints, optimize_linear_with_protected};
use super::predicates::{compute_variable_frequency, is_linear, is_trivially_satisfied};
use super::substitution::{
    apply_substitution_in_place, apply_substitution_to_constraint_in_place, solve_for_variable,
};
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use super::union_find::UnionFind;
use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Clusters above this size fall back to the greedy iterative
/// eliminator (`optimize_linear_with_protected`) instead of running
/// the per-cluster Gaussian solver. The Gauss inner loop is
/// O(cluster_size^2 * avg_density) per round -- on bit-heavy circuits
/// like SHA-256(64) the linear constraints can form one connected
/// component of 30k+ nodes via shared bit signals, where full
/// reduction is intractable in this conservative path. Markowitz
/// pivoting / fill-in management (the path that would handle giant
/// clusters in finite time) is out of scope.
///
/// Falling back to greedy on the cluster's subset is sound: the
/// greedy and Gauss algorithms reach the same linear fixpoint (just
/// via different orderings), so the substitution map produced is
/// equivalent. The min-occurrence picker only applies inside the
/// Gauss path and therefore only for clusters in
/// `[MIN_OCCURRENCE_LOWER, CLUSTER_FALLBACK_THRESHOLD]`; outside that
/// band we either use Gauss + max-frequency (small clusters) or
/// greedy fallback (giant clusters).
///
/// 500 was chosen empirically by re-running the full circomlib
/// benchmark with the clustered driver enabled: thresholds >= 1000
/// produced 5-15x runtime regressions on EscalarMulAny(254) and
/// MiMCSponge(2,220,1) without recovering observable constraint
/// counts (their clusters in the 1000-5000 range yielded the same
/// fixpoint as greedy on those templates). 500 keeps the gauss path
/// active where the algorithmic difference matters (LessThan(8):
/// 10 -> 9 constraints) without the runtime regression on circuits
/// with mid-sized clusters.
const CLUSTER_FALLBACK_THRESHOLD: usize = 500;

/// Lower bound for switching from max-frequency picker to
/// min-occurrence picker. Mirrors circom 2.2.x's threshold
/// (`circom_algebra/src/simplification_utils.rs:548`, the `min`
/// constant in `full_simplification`).
const MIN_OCCURRENCE_LOWER: usize = 350;

/// Upper bound for the min-occurrence picker. Above this, even
/// scanning per-pivot for the smallest occurrence count becomes a
/// notable cost; circom switches back to a coarser strategy. We
/// already have a tighter ceiling (`CLUSTER_FALLBACK_THRESHOLD`) so
/// this constant is documented for parity but never reached in
/// practice -- by the time a cluster crosses 5000 we have already
/// fallen back to greedy.
const MIN_OCCURRENCE_UPPER: usize = 1_000_000;

/// Pivot variable selection strategy used by the per-cluster Gaussian
/// solver. Determined by cluster size: clusters in
/// `[MIN_OCCURRENCE_LOWER, MIN_OCCURRENCE_UPPER)` use
/// `MinOccurrence`, others use `MaxFrequency`. Mirrors circom 2.2.x
/// (`circom_algebra/src/simplification_utils.rs`):
/// `apply_less_ocurrences` switches to `take_signal_4` (min-occ)
/// inside the same band.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Picker {
    MaxFrequency,
    MinOccurrence,
}

impl Picker {
    fn for_cluster_size(size: usize) -> Self {
        if (MIN_OCCURRENCE_LOWER..MIN_OCCURRENCE_UPPER).contains(&size) {
            Picker::MinOccurrence
        } else {
            Picker::MaxFrequency
        }
    }
}

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
pub(super) fn build_clusters_by_signal<F: FieldBackend>(
    linear_constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
) -> Vec<Vec<usize>> {
    let n = linear_constraints.len();
    let mut uf = UnionFind::new(n);

    // For each signal index, remember the first constraint that owns
    // it; subsequent owners union with that first. The first-owner
    // table is keyed on signal index up to the maximum referenced
    // (sized lazily via HashMap, since the wire-index space is sparse
    // here -- we only see indices appearing in the linear subset).
    let mut first_owner: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();

    for (idx, constraint) in linear_constraints.iter().enumerate() {
        // Walk only constraints that ARE linear. Non-linear ones
        // contribute no signals to the Union-Find -- they end up as
        // their own singleton cluster, which the caller can ignore
        // (the Gauss step has nothing to do with them).
        let Some((_k, other_lc, c_lc)) = is_linear(constraint) else {
            continue;
        };

        for (var, _coeff) in other_lc.terms().iter().chain(c_lc.terms().iter()) {
            let sig = var.index();
            if sig == Variable::ONE.index() || protected.contains(&sig) {
                continue;
            }
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

/// Pick a substitution variable from `lc` according to `picker`.
///
/// `MaxFrequency`: delegates to the existing
/// [`solve_for_variable`] -- pick the non-protected term with the
/// highest occurrence count, tie-break by highest index. This is the
/// achronyme-historical heuristic.
///
/// `MinOccurrence`: pick the non-protected term with the **lowest**
/// occurrence count, tie-break by **highest** index. Mirrors circom
/// 2.2.x's `take_signal_4`
/// (`circom_algebra/src/simplification_utils.rs:380`); the rationale
/// is that substituting a rarely-occurring variable propagates the
/// fewest changes, keeping subsequent rows shorter and reducing
/// overall fill-in.
fn solve_for_variable_with_picker<F: FieldBackend>(
    lc: LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &HashMap<usize, usize>,
    picker: Picker,
) -> Option<(Variable, LinearCombination<F>)> {
    match picker {
        Picker::MaxFrequency => solve_for_variable(lc, protected, var_freq),
        Picker::MinOccurrence => {
            let simplified = lc.simplify();
            let mut best: Option<(Variable, FieldElement<F>, usize)> = None;
            for (var, coeff) in simplified.terms() {
                if protected.contains(&var.index()) || var.index() == Variable::ONE.index() {
                    continue;
                }
                let freq = var_freq.get(&var.index()).copied().unwrap_or(0);
                match &best {
                    None => best = Some((*var, *coeff, freq)),
                    Some((prev_var, _, prev_freq)) => {
                        // pick MIN freq; tie-break by MAX index
                        if freq < *prev_freq
                            || (freq == *prev_freq && var.index() > prev_var.index())
                        {
                            best = Some((*var, *coeff, freq));
                        }
                    }
                }
            }
            let (target_var, target_coeff, _) = best?;
            let neg_inv = target_coeff.neg().inv()?;
            let mut result = LinearCombination::<F>::zero();
            for (var, coeff) in simplified.terms() {
                if *var == target_var {
                    continue;
                }
                result.add_term(*var, coeff.mul(&neg_inv));
            }
            Some((target_var, result))
        }
    }
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
pub(super) fn solve_cluster_linear<F: FieldBackend>(
    cluster_constraints: Vec<Constraint<F>>,
    protected: &HashSet<usize>,
    var_freq: &HashMap<usize, usize>,
) -> (SubstitutionMap<F>, Vec<Constraint<F>>) {
    let cluster_size = cluster_constraints.len();
    let picker = Picker::for_cluster_size(cluster_size);

    // Linearize: build the per-constraint "must equal zero" LC.
    let mut zero_lcs: Vec<LinearCombination<F>> = Vec::new();
    let mut residual: Vec<Constraint<F>> = Vec::new();

    for c in cluster_constraints {
        match is_linear(&c) {
            Some((k, other, c_lc)) => {
                // Constraint encodes k * other = c_lc, i.e.
                // c_lc - k*other = 0.
                let combined = (c_lc - (other * k)).simplify();
                zero_lcs.push(combined);
            }
            None => residual.push(c),
        }
    }

    let mut subs: SubstitutionMap<F> = HashMap::new();

    loop {
        // Build the "effective protected" set: original protected
        // variables plus everything we have already substituted. Once
        // a variable is substituted it must never be picked again --
        // doing so would create a chain in the substitution map and
        // break the acyclic invariant the witness fixup relies on.
        let mut effective_protected = protected.clone();
        for var_idx in subs.keys() {
            effective_protected.insert(*var_idx);
        }

        // Find the first row that admits a substitution.
        let mut found: Option<(usize, Variable, LinearCombination<F>)> = None;
        for (i, lc) in zero_lcs.iter().enumerate() {
            if let Some((var, expr)) =
                solve_for_variable_with_picker(lc.clone(), &effective_protected, var_freq, picker)
            {
                found = Some((i, var, expr));
                break;
            }
        }

        let Some((row_idx, var, expr)) = found else {
            break;
        };
        zero_lcs.swap_remove(row_idx);

        // Apply the new substitution to all remaining rows + compose
        // it into previously-recorded substitutions so the final map
        // is acyclic.
        let mut single_sub: SubstitutionMap<F> = HashMap::new();
        single_sub.insert(var.index(), expr.clone());

        for lc in zero_lcs.iter_mut() {
            apply_substitution_in_place(lc, &single_sub);
        }
        for prev_expr in subs.values_mut() {
            apply_substitution_in_place(prev_expr, &single_sub);
        }
        subs.insert(var.index(), expr);
    }

    // Convert any remaining non-empty rows back to constraint form
    // (`1 * lc = 0`) so the caller can keep them in the system.
    // Empty rows are tautologies after substitution; skip them.
    for lc in zero_lcs {
        let lc_simp = lc.simplify();
        if !lc_simp.terms().is_empty() {
            residual.push(Constraint {
                a: LinearCombination::from_constant(FieldElement::one()),
                b: lc_simp,
                c: LinearCombination::zero(),
            });
        }
    }

    (subs, residual)
}

/// Run cluster-based linear constraint elimination to fixpoint.
///
/// Mirrors `optimize_linear` (the greedy round-by-round eliminator)
/// but partitions linear constraints into connected components by
/// shared signal each round and runs Gaussian elimination per cluster
/// (`solve_cluster_linear`). The fixpoint, dedup, and trivial-sweep
/// post-processing are identical to the greedy path.
///
/// Protected variables (ONE + public inputs, indices
/// `0..=num_pub_inputs`) are never substituted.
pub fn optimize_linear_clustered<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_linear_clustered_with_protected(constraints, num_pub_inputs, &HashSet::new())
}

/// Like `optimize_linear_clustered`, but also protects extra variable
/// indices from substitution. Used by O2's outer loop to shield
/// decompose aux wires.
pub(super) fn optimize_linear_clustered_with_protected<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
    extra_protected: &HashSet<usize>,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    let constraints_before = constraints.len();

    // Protected: ONE (0) + public inputs (1..=num_pub_inputs) + extra.
    let mut protected: HashSet<usize> = (0..=num_pub_inputs).collect();
    protected.extend(extra_protected);

    let mut all_subs: SubstitutionMap<F> = HashMap::new();
    let mut rounds = 0usize;
    let mut round_details: Vec<(usize, usize)> = Vec::new();
    let mut total_trivial_removed = 0usize;

    loop {
        rounds += 1;

        let var_freq = compute_variable_frequency(constraints);

        // Round-protected: original protected + everything substituted
        // in earlier rounds. Once a variable has been substituted it
        // must never be picked again -- doing so would create chains
        // in the substitution map and break the acyclic invariant
        // witness fixup relies on.
        let mut round_protected = protected.clone();
        for var_idx in all_subs.keys() {
            round_protected.insert(*var_idx);
        }

        // Partition constraints into linear (eligible for cluster
        // Gauss) and non-linear (passed through unchanged this round).
        let mut linear_indices: Vec<usize> = Vec::new();
        let mut linear_constraints: Vec<Constraint<F>> = Vec::new();
        for (idx, c) in constraints.iter().enumerate() {
            if is_linear(c).is_some() {
                linear_indices.push(idx);
                linear_constraints.push(c.clone());
            }
        }

        let nonlinear_before = constraints.len() - linear_constraints.len();

        // Cluster the linear constraints by shared signal.
        let clusters = build_clusters_by_signal(&linear_constraints, &round_protected);

        // Solve each cluster and merge results.
        let mut round_subs: SubstitutionMap<F> = HashMap::new();
        let mut residuals: Vec<Constraint<F>> = Vec::new();
        for cluster in &clusters {
            let cluster_cons: Vec<Constraint<F>> = cluster
                .iter()
                .map(|&i| linear_constraints[i].clone())
                .collect();
            if cluster.len() > CLUSTER_FALLBACK_THRESHOLD {
                // Giant cluster -- delegate to the greedy iterative
                // eliminator. Greedy reaches the same linear fixpoint
                // as Gauss (modulo substitution-key choice) but
                // applies substitutions in batched rounds, which
                // scales linearly per round in cluster size instead
                // of O(n^2) per round. Soundness is preserved; the
                // resulting substitution map keys may differ from
                // what Gauss would have picked, but both are valid
                // closures of the same equivalence relation.
                //
                // We pass `0` for num_pub_inputs because round_protected
                // already contains the public-input indices (plus aux
                // wires + previously-substituted vars).
                let mut subset = cluster_cons;
                let (greedy_subs, _greedy_stats) =
                    optimize_linear_with_protected(&mut subset, 0, &round_protected);
                for (k, v) in greedy_subs {
                    round_subs.insert(k, v);
                }
                residuals.extend(subset);
                continue;
            }
            let (subs, residual) = solve_cluster_linear(cluster_cons, &round_protected, &var_freq);
            // Clusters are disjoint over non-protected signals, so
            // their substitution-map keys are disjoint by
            // construction. Inserting unconditionally is safe.
            for (k, v) in subs {
                round_subs.insert(k, v);
            }
            residuals.extend(residual);
        }

        if round_subs.is_empty() {
            rounds -= 1; // do not count empty round
            break;
        }

        let linear_eliminated = linear_constraints.len() - residuals.len();

        // Build the next constraint set: keep non-linear constraints
        // (with substitutions applied) + new residuals (already had
        // their own cluster's substitutions applied internally; apply
        // round_subs so cross-cluster effects on shared protected
        // signals fold in).
        // Compact non-linear constraints in place + apply round_subs to
        // each. Two-cursor sweep avoids allocating a fresh `Vec`.
        let linear_index_set: HashSet<usize> = linear_indices.iter().copied().collect();
        let n = constraints.len();
        let mut write = 0usize;
        for read in 0..n {
            if linear_index_set.contains(&read) {
                continue;
            }
            if write != read {
                constraints.swap(write, read);
            }
            apply_substitution_to_constraint_in_place(&mut constraints[write], &round_subs);
            write += 1;
        }
        constraints.truncate(write);
        for mut r in residuals {
            apply_substitution_to_constraint_in_place(&mut r, &round_subs);
            constraints.push(r);
        }

        // Sweep trivially-satisfied constraints (0*B=0, k*LC=k*LC, etc.).
        let before_trivial = constraints.len();
        constraints.retain(|c| !is_trivially_satisfied(c));
        let trivial_this_round = before_trivial - constraints.len();
        total_trivial_removed += trivial_this_round;

        // Count newly-linear constraints exposed by the substitutions
        // applied to non-linears.
        let nonlinear_after = constraints
            .iter()
            .filter(|c| is_linear(c).is_none())
            .count();
        let newly_linear = nonlinear_before.saturating_sub(nonlinear_after);

        round_details.push((linear_eliminated, newly_linear));

        // Compose with previous substitutions: apply new subs to old
        // expressions in place so the final map remains acyclic.
        for expr in all_subs.values_mut() {
            apply_substitution_in_place(expr, &round_subs);
        }
        all_subs.extend(round_subs);
    }

    // Post-processing identical to optimize_linear: dedup non-linear
    // constraints (after substitution different template instances can
    // become identical) + final trivial sweep.
    let before_dedup = constraints.len();
    deduplicate_constraints(constraints);
    let duplicates_removed = before_dedup - constraints.len();

    let before_final_trivial = constraints.len();
    constraints.retain(|c| !is_trivially_satisfied(c));
    total_trivial_removed += before_final_trivial - constraints.len();

    let result = R1CSOptimizeResult {
        constraints_before,
        constraints_after: constraints.len(),
        variables_eliminated: all_subs.len(),
        duplicates_removed,
        trivial_removed: total_trivial_removed,
        rounds,
        round_details,
    };

    (all_subs, result)
}
