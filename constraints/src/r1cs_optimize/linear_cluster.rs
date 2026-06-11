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

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::FieldBackend;

mod gauss;
mod parallel;
mod picker;
mod touch_profile;

use super::linear::deduplicate_constraints;
use super::predicates::{
    compute_variable_frequency, count_nonlinear_constraints, is_linear,
    retain_nontrivial_constraints,
};
use super::substitution::{apply_substitution_in_place, apply_substitution_to_constraint_in_place};
use super::timing::O1Timings;
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use crate::r1cs::{Constraint, LinearCombination};
pub(super) use gauss::{build_clusters_by_signal, solve_cluster_linear};
use parallel::{apply_substitutions_to_all_constraints, solve_clusters_ordered};
use touch_profile::log_substitution_touch;

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

    let mut all_subs: SubstitutionMap<F> = FxHashMap::default();
    let mut rounds = 0usize;
    let mut round_details: Vec<(usize, usize)> = Vec::new();
    let mut total_trivial_removed = 0usize;
    let mut timings = O1Timings::from_env();
    loop {
        rounds += 1;

        let var_freq = timings.time(0, || compute_variable_frequency(constraints));

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
        // Linear rows are MOVED out behind an empty placeholder, not
        // cloned: the masked slots are never read again — the
        // substitution pass skips them by mask and the compaction
        // sweep swaps without inspecting content — so the round avoids
        // holding a second copy of every linear row's term heap.
        let (linear_indices, linear_constraints) = timings.time(1, || {
            let mut linear_indices: Vec<usize> = Vec::new();
            for (idx, c) in constraints.iter().enumerate() {
                if is_linear(c).is_some() {
                    linear_indices.push(idx);
                }
            }
            let mut linear_constraints: Vec<Constraint<F>> =
                Vec::with_capacity(linear_indices.len());
            for &idx in &linear_indices {
                let placeholder = Constraint {
                    a: LinearCombination::zero(),
                    b: LinearCombination::zero(),
                    c: LinearCombination::zero(),
                };
                linear_constraints.push(std::mem::replace(&mut constraints[idx], placeholder));
            }
            (linear_indices, linear_constraints)
        });

        // Compact the survivors immediately: the moved-out slots are
        // empty placeholders, and removing them now (instead of after
        // the solve) releases the spine's pre-optimize capacity tail
        // before the round's memory peak. Survivors keep their
        // original relative order — identical to the post-solve mask
        // sweep this replaces.
        timings.time(5, || {
            let mut next_linear = linear_indices.iter().peekable();
            let mut write = 0usize;
            for read in 0..constraints.len() {
                if next_linear.peek() == Some(&&read) {
                    next_linear.next();
                    continue;
                }
                if write != read {
                    constraints.swap(write, read);
                }
                write += 1;
            }
            constraints.truncate(write);
            if constraints.capacity() > constraints.len().saturating_mul(2) {
                constraints.shrink_to_fit();
            }
        });

        let nonlinear_before = constraints.len();

        // Cluster the linear constraints by shared signal.
        let clusters = timings.time(2, || {
            build_clusters_by_signal(&linear_constraints, &round_protected)
        });
        if timings.enabled() {
            let max_cluster = clusters.iter().map(Vec::len).max().unwrap_or(0);
            let fallback_clusters = clusters
                .iter()
                .filter(|cluster| cluster.len() > CLUSTER_FALLBACK_THRESHOLD)
                .count();
            let fallback_constraints: usize = clusters
                .iter()
                .filter(|cluster| cluster.len() > CLUSTER_FALLBACK_THRESHOLD)
                .map(Vec::len)
                .sum();
            eprintln!(
                "[O1] round {rounds} constraints={} linear={} clusters={} max_cluster={} \
                 fallback_clusters={} fallback_constraints={}",
                constraints.len(),
                linear_constraints.len(),
                clusters.len(),
                max_cluster,
                fallback_clusters,
                fallback_constraints,
            );
        }

        // Solve clusters independently, then merge in cluster-index order.
        let mut round_subs: SubstitutionMap<F> = FxHashMap::default();
        let mut residuals: Vec<Constraint<F>> = Vec::new();

        // Distribute the moved rows into per-cluster owned vecs
        // (clusters partition 0..linear_total exactly). Rows of
        // clusters that produce substitutions are freed inside the
        // solve as each cluster completes; rows of no-subs clusters
        // come back for the all-empty-round restore.
        let linear_total = linear_constraints.len();
        let cluster_inputs: Vec<Vec<Constraint<F>>> = {
            let mut slots: Vec<Option<Constraint<F>>> =
                linear_constraints.into_iter().map(Some).collect();
            clusters
                .iter()
                .map(|cluster| {
                    cluster
                        .iter()
                        .map(|&i| slots[i].take().expect("clusters partition the linear rows"))
                        .collect()
                })
                .collect()
        };

        let solved_clusters = timings.time(3, || {
            solve_clusters_ordered(cluster_inputs, &round_protected, &var_freq)
        });
        if timings.enabled() {
            let fallback_rounds: usize = solved_clusters.iter().map(|s| s.fallback_rounds).sum();
            let fallback_scans: usize = solved_clusters
                .iter()
                .map(|s| s.fallback_len * s.fallback_rounds)
                .sum();
            eprintln!(
                "[O1] round {rounds} fallback_inner_rounds={fallback_rounds} \
                 fallback_cluster_round_scans={fallback_scans}"
            );
        }
        let total_round_subs: usize = solved_clusters.iter().map(|s| s.subs.len()).sum();
        round_subs.reserve(total_round_subs);
        let mut unsolved_rows: Vec<(usize, Vec<Constraint<F>>)> = Vec::new();
        for (cluster_idx, solved) in solved_clusters.into_iter().enumerate() {
            for (k, v) in solved.subs {
                round_subs.insert(k, v);
            }
            residuals.extend(solved.residual);
            if let Some(rows) = solved.unsolved_rows {
                unsolved_rows.push((cluster_idx, rows));
            }
        }

        if round_subs.is_empty() {
            // Nothing was solved: every cluster returned its pristine
            // rows. Rebuild the exact pre-round layout — survivors and
            // restored rows re-interleave by original index
            // (linear_indices is ascending) — so the probe round
            // leaves `constraints` unchanged. The cluster residuals
            // are rewrites of these same rows and are discarded.
            let mut restored: Vec<Option<Constraint<F>>> =
                (0..linear_total).map(|_| None).collect();
            for (cluster_idx, rows) in unsolved_rows {
                for (j, row) in rows.into_iter().enumerate() {
                    restored[clusters[cluster_idx][j]] = Some(row);
                }
            }
            let survivors = std::mem::take(constraints);
            let total = survivors.len() + linear_total;
            let mut rebuilt: Vec<Constraint<F>> = Vec::with_capacity(total);
            let mut survivor_iter = survivors.into_iter();
            let mut linear_iter = linear_indices.iter().zip(restored).peekable();
            for idx in 0..total {
                match linear_iter.peek() {
                    Some((&pos, _)) if pos == idx => {
                        let (_, row) = linear_iter.next().expect("peeked entry");
                        rebuilt.push(row.expect("every cluster returns rows on the empty round"));
                    }
                    _ => rebuilt.push(survivor_iter.next().expect("survivor count matches layout")),
                }
            }
            *constraints = rebuilt;
            rounds -= 1; // do not count empty round
            break;
        }

        let linear_eliminated = linear_total - residuals.len();
        // No-subs clusters' pristine rows, the frequency counts, and
        // the cluster index lists are dead from here (the surviving
        // rewrites are in `residuals`); free them before the
        // substitution pass allocates its fill-in.
        drop(unsolved_rows);
        drop(var_freq);
        drop(clusters);

        // Build the next constraint set: the survivors (already
        // compacted at classify time) receive the round's
        // substitutions, then the new residuals are appended (their
        // own cluster's substitutions were applied internally; apply
        // round_subs so cross-cluster effects on shared protected
        // signals fold in).
        if timings.enabled() {
            let no_mask = vec![false; constraints.len()];
            log_substitution_touch(rounds, constraints, &no_mask, &residuals, &round_subs);
        }
        timings.time(4, || {
            apply_substitutions_to_all_constraints(constraints, &round_subs);
        });

        timings.time(5, || {
            for mut r in residuals {
                apply_substitution_to_constraint_in_place(&mut r, &round_subs);
                constraints.push(r);
            }
        });

        // Sweep trivially-satisfied constraints (0*B=0, k*LC=k*LC, etc.).
        let trivial_this_round = timings.time(6, || retain_nontrivial_constraints(constraints));
        total_trivial_removed += trivial_this_round;

        // The first round typically eliminates the majority of all
        // rows; without a shrink the spine's pre-optimize push-doubling
        // capacity would stay resident through the remaining rounds and
        // the dedup. Only shrink on real waste.
        if constraints.capacity() > constraints.len().saturating_mul(2) {
            constraints.shrink_to_fit();
        }

        // Count newly-linear constraints exposed by the substitutions
        // applied to non-linears.
        let nonlinear_after = timings.time(7, || count_nonlinear_constraints(constraints));
        let newly_linear = nonlinear_before.saturating_sub(nonlinear_after);

        round_details.push((linear_eliminated, newly_linear));

        // Compose with previous substitutions: apply new subs to old
        // expressions in place so the final map remains acyclic.
        timings.time(8, || {
            for expr in all_subs.values_mut() {
                apply_substitution_in_place(expr, &round_subs);
            }
            all_subs.extend(round_subs);
        });
    }

    // A giant cluster falls back to the greedy batch eliminator, whose
    // map can chain a wire to another eliminated the same round; left
    // unflattened that wire dangles in a survivor (forgeable). Break those
    // cycles and rewrite every survivor against the map so none references
    // an eliminated wire; rank-deficient cycles re-emit the rows their
    // deficiency exposes. The Gauss path is already eager-canonical, and
    // clusters partition variables, so the unioned map is acyclic outside
    // the greedy's contribution -- this only does real work there.
    super::flatten::canonicalize_against_constraints(&mut all_subs, constraints);

    // Post-processing identical to optimize_linear: dedup non-linear
    // constraints (after substitution different template instances can
    // become identical) + final trivial sweep.
    let before_dedup = constraints.len();
    timings.time(9, || deduplicate_constraints(constraints));
    let duplicates_removed = before_dedup - constraints.len();

    total_trivial_removed += timings.time(10, || retain_nontrivial_constraints(constraints));

    let result = R1CSOptimizeResult {
        constraints_before,
        constraints_after: constraints.len(),
        variables_eliminated: all_subs.len(),
        duplicates_removed,
        trivial_removed: total_trivial_removed,
        rounds,
        round_details,
    };

    timings.print(
        "O1",
        &[
            "frequency",
            "classify",
            "cluster",
            "solve",
            "substitute",
            "compact",
            "trivial",
            "count nonlinear",
            "compose subs",
            "dedup",
            "final trivial",
        ],
    );

    (all_subs, result)
}
