//! O1 pass — linear constraint elimination + constraint deduplication.
//!
//! `optimize_linear` is the public entry; it runs to fixpoint,
//! per-round:
//!
//! 1. Compute variable-frequency heuristic.
//! 2. For each still-linear constraint, solve for the best
//!    non-protected variable and record the substitution.
//! 3. Drop solved constraints, apply substitutions to the rest,
//!    sweep trivially-satisfied constraints.
//! 4. Compose new substitutions into previously-recorded ones.
//!
//! After the fixpoint converges, two clean-up phases run once:
//! `deduplicate_constraints` (commutative A×B=C hash) and a final
//! trivial-satisfaction sweep.
//!
//! `optimize_linear_with_protected` is the internal variant that
//! accepts an extra set of variable indices to protect — used by
//! the O2 pass to shield decomposition wires during DEDUCE
//! processing.

use std::collections::HashSet;

use rayon::prelude::*;
use rustc_hash::FxHashMap;

use memory::FieldBackend;

use super::predicates::{
    compute_variable_frequency, count_nonlinear_constraints, is_linear, lc_fingerprint,
    retain_nontrivial_constraints,
};
use super::substitution::{
    apply_substitution_in_place, apply_substitution_to_constraint_in_place,
    solve_for_variable_simplified, InvCache,
};
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use crate::r1cs::Constraint;

const PARALLEL_DEDUP_THRESHOLD: usize = 512;
const PARALLEL_GREEDY_SUBSTITUTION_THRESHOLD: usize = 512;

/// Run greedy iterative linear constraint elimination to fixpoint.
///
/// Protected variables (ONE + public inputs, indices `0..=num_pub_inputs`)
/// are never substituted away.
///
/// Not the public O1 driver -- `r1cs_optimize::optimize_linear` is
/// an alias for `linear_cluster::optimize_linear_clustered`. This
/// function is preserved as a `pub(super)` helper because:
///   1. `linear_cluster::optimize_linear_clustered_with_protected`
///      uses it as the per-cluster fallback for clusters whose size
///      exceeds `CLUSTER_FALLBACK_THRESHOLD` (greedy reaches the same
///      linear fixpoint as Gauss but in batched rounds, scaling
///      linearly per round in cluster size).
///   2. A handful of internal tests still exercise the greedy
///      heuristic explicitly (e.g. `test_frequency_heuristic_greedy`).
#[allow(dead_code)] // wrapper retained for tests exercising greedy directly
pub(super) fn optimize_linear_greedy<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_linear_with_protected(constraints, num_pub_inputs, &HashSet::new())
}

/// Like `optimize_linear_greedy`, but also protects additional variable
/// indices from substitution. Used by:
/// - `linear_cluster::optimize_linear_clustered_with_protected` as the
///   per-cluster fallback for clusters above
///   `CLUSTER_FALLBACK_THRESHOLD`.
/// - `deduce::optimize_o2_with_deducer` historically; the current
///   call sites use the clustered variant.
pub(super) fn optimize_linear_with_protected<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
    extra_protected: &HashSet<usize>,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    let constraints_before = constraints.len();

    // Protected: ONE (0) + public inputs (1..=num_pub_inputs) + extra
    let mut protected: HashSet<usize> = (0..=num_pub_inputs).collect();
    protected.extend(extra_protected);

    let mut all_subs: SubstitutionMap<F> = FxHashMap::default();
    let mut rounds = 0usize;
    let mut round_details: Vec<(usize, usize)> = Vec::new();
    let mut total_trivial_removed = 0usize;
    // Memoize pivot inversions across all rounds. With ≥93 % duplicate-rate
    // observed on every workload measured (99.98 % on SHA-256 message-block
    // bit operations), the working set stays in the low hundreds and the
    // map dominates the saved Fermat-LT `pow(p-2)` cost.
    let mut inv_cache: InvCache<F> = FxHashMap::default();

    loop {
        rounds += 1;

        // Compute variable frequency for this round's heuristic
        let var_freq = compute_variable_frequency(constraints);

        let mut round_subs: SubstitutionMap<F> = FxHashMap::default();
        let mut to_remove: HashSet<usize> = HashSet::new();

        // Also protect variables already substituted in previous rounds
        let mut round_protected = protected.clone();
        for var_idx in all_subs.keys() {
            round_protected.insert(*var_idx);
        }

        // Count non-linear constraints before this round (for instrumentation)
        let nonlinear_before = count_nonlinear_constraints(constraints);

        // `round_protected` is mutated in place as new substitutions are
        // claimed: once a variable is chosen this round, no later constraint
        // may solve for it again. Cloning the set per iteration (and
        // re-inserting `round_subs.keys()` each time) made the loop quadratic
        // in the number of claimed variables — for circuits like
        // EscalarMulAny(254) where ~3 000 vars are eliminated in a single
        // round, that dominated O1 runtime.
        for (idx, constraint) in constraints.iter().enumerate() {
            if let Some((k, other_lc, c_lc)) = is_linear(constraint) {
                // Constraint encodes: k * other_lc = c_lc
                // i.e., c_lc - k * other_lc = 0
                let combined = (c_lc - (other_lc * k)).simplify();

                if let Some((var, expr)) = solve_for_variable_simplified(
                    &combined,
                    &round_protected,
                    &var_freq,
                    &mut inv_cache,
                ) {
                    round_protected.insert(var.index());
                    round_subs.insert(var.index(), expr);
                    to_remove.insert(idx);
                }
            }
        }

        if round_subs.is_empty() {
            rounds -= 1; // Don't count empty round
            break;
        }

        let linear_eliminated = to_remove.len();

        // Drop eliminated constraints + apply substitutions in place to
        // the survivors. Two-cursor compaction over the existing Vec so
        // we avoid allocating a fresh Vec<Constraint> per round.
        let n = constraints.len();
        let remove_mask: Vec<bool> = (0..n).map(|idx| to_remove.contains(&idx)).collect();
        if n >= PARALLEL_GREEDY_SUBSTITUTION_THRESHOLD {
            constraints
                .par_iter_mut()
                .zip(remove_mask.par_iter())
                .for_each(|(constraint, remove)| {
                    if !*remove {
                        apply_substitution_to_constraint_in_place(constraint, &round_subs);
                    }
                });
        }

        let mut write = 0usize;
        for (read, remove) in remove_mask.into_iter().enumerate() {
            if remove {
                continue;
            }
            if write != read {
                constraints.swap(write, read);
            }
            if n < PARALLEL_GREEDY_SUBSTITUTION_THRESHOLD {
                apply_substitution_to_constraint_in_place(&mut constraints[write], &round_subs);
            }
            write += 1;
        }
        constraints.truncate(write);

        // Remove trivially-satisfied constraints (0*B=0, k1*k2=k3)
        let trivial_this_round = retain_nontrivial_constraints(constraints);
        total_trivial_removed += trivial_this_round;

        // Count how many non-linear constraints became linear after substitution
        let nonlinear_after = count_nonlinear_constraints(constraints);
        let newly_linear = nonlinear_before.saturating_sub(nonlinear_after + linear_eliminated);

        round_details.push((linear_eliminated, newly_linear));

        // Compose with previous substitutions: apply new subs to old
        // expressions in place. Avoids the prior allocation of a fresh
        // LC per substitution-map entry per round.
        for expr in all_subs.values_mut() {
            apply_substitution_in_place(expr, &round_subs);
        }
        all_subs.extend(round_subs);
    }

    // Step 2: Remove duplicate non-linear constraints.
    // After variable substitution, constraints from different template instances
    // (wired via AssertEq) can become identical. Deduplicate by hashing.
    let before_dedup = constraints.len();
    deduplicate_constraints(constraints);
    let duplicates_removed = before_dedup - constraints.len();

    // Step 3: Final trivial constraint removal (post-dedup may expose more).
    total_trivial_removed += retain_nontrivial_constraints(constraints);

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

/// Remove duplicate constraints (same A, B, C after simplification).
/// Also removes commuted duplicates (A*B=C == B*A=C).
pub(super) fn deduplicate_constraints<F: FieldBackend>(constraints: &mut Vec<Constraint<F>>) {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(constraints.len());
    if constraints.len() >= PARALLEL_DEDUP_THRESHOLD {
        let keys: Vec<Vec<u8>> = constraints.par_iter().map(constraint_fingerprint).collect();
        let mut write = 0usize;
        for (read, key) in keys.into_iter().enumerate() {
            if !seen.insert(key) {
                continue;
            }
            if write != read {
                constraints.swap(write, read);
            }
            write += 1;
        }
        constraints.truncate(write);
        return;
    }

    constraints.retain(|c| seen.insert(constraint_fingerprint(c)));
}

fn constraint_fingerprint<F: FieldBackend>(constraint: &Constraint<F>) -> Vec<u8> {
    let fa = lc_fingerprint(&constraint.a);
    let fb = lc_fingerprint(&constraint.b);
    let fc = lc_fingerprint(&constraint.c);

    // Canonical key: sort A,B to handle commutativity (A*B=C == B*A=C).
    let (fa, fb) = if fa <= fb { (fa, fb) } else { (fb, fa) };

    let mut key = Vec::with_capacity(fa.len() + fb.len() + fc.len() + 2);
    key.extend_from_slice(&fa);
    key.push(0xFF);
    key.extend_from_slice(&fb);
    key.push(0xFF);
    key.extend_from_slice(&fc);
    key
}
