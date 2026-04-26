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

use std::collections::{HashMap, HashSet};

use memory::FieldBackend;

use super::predicates::{
    compute_variable_frequency, is_linear, is_trivially_satisfied, lc_fingerprint,
};
use super::substitution::{
    apply_substitution, apply_substitution_to_constraint, solve_for_variable,
};
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use crate::r1cs::Constraint;

/// Run greedy iterative linear constraint elimination to fixpoint.
///
/// Protected variables (ONE + public inputs, indices `0..=num_pub_inputs`)
/// are never substituted away.
///
/// **Phase 6 note:** this entry is no longer the public O1 driver --
/// `r1cs_optimize::optimize_linear` is now an alias for the
/// cluster-based driver (`linear_cluster::optimize_linear_clustered`).
/// This function is preserved as a `pub(super)` helper because:
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
/// - `deduce::optimize_o2_with_deducer` historically; phase 6 swaps
///   those call sites to the clustered variant.
pub(super) fn optimize_linear_with_protected<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
    extra_protected: &HashSet<usize>,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    let constraints_before = constraints.len();

    // Protected: ONE (0) + public inputs (1..=num_pub_inputs) + extra
    let mut protected: HashSet<usize> = (0..=num_pub_inputs).collect();
    protected.extend(extra_protected);

    let mut all_subs: SubstitutionMap<F> = HashMap::new();
    let mut rounds = 0usize;
    let mut round_details: Vec<(usize, usize)> = Vec::new();
    let mut total_trivial_removed = 0usize;

    loop {
        rounds += 1;

        // Compute variable frequency for this round's heuristic
        let var_freq = compute_variable_frequency(constraints);

        let mut round_subs: SubstitutionMap<F> = HashMap::new();
        let mut to_remove: HashSet<usize> = HashSet::new();

        // Also protect variables already substituted in previous rounds
        let mut round_protected = protected.clone();
        for var_idx in all_subs.keys() {
            round_protected.insert(*var_idx);
        }

        // Count non-linear constraints before this round (for instrumentation)
        let nonlinear_before = constraints
            .iter()
            .filter(|c| is_linear(c).is_none())
            .count();

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
                let combined = c_lc - (other_lc * k);

                if let Some((var, expr)) = solve_for_variable(combined, &round_protected, &var_freq)
                {
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

        // Remove eliminated constraints and apply substitutions to the rest
        *constraints = constraints
            .iter()
            .enumerate()
            .filter(|(idx, _)| !to_remove.contains(idx))
            .map(|(_, c)| apply_substitution_to_constraint(c, &round_subs))
            .collect();

        // Remove trivially-satisfied constraints (0*B=0, k1*k2=k3)
        let before_trivial = constraints.len();
        constraints.retain(|c| !is_trivially_satisfied(c));
        let trivial_this_round = before_trivial - constraints.len();
        total_trivial_removed += trivial_this_round;

        // Count how many non-linear constraints became linear after substitution
        let nonlinear_after = constraints
            .iter()
            .filter(|c| is_linear(c).is_none())
            .count();
        let newly_linear = nonlinear_before.saturating_sub(nonlinear_after + linear_eliminated);

        round_details.push((linear_eliminated, newly_linear));

        // Compose with previous substitutions: apply new subs to old expressions
        for expr in all_subs.values_mut() {
            *expr = apply_substitution(expr, &round_subs);
        }
        all_subs.extend(round_subs);
    }

    // Phase 2: Remove duplicate non-linear constraints.
    // After variable substitution, constraints from different template instances
    // (wired via AssertEq) can become identical. Deduplicate by hashing.
    let before_dedup = constraints.len();
    deduplicate_constraints(constraints);
    let duplicates_removed = before_dedup - constraints.len();

    // Phase 3: Final trivial constraint removal (post-dedup may expose more).
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

/// Remove duplicate constraints (same A, B, C after simplification).
/// Also removes commuted duplicates (A*B=C == B*A=C).
pub(super) fn deduplicate_constraints<F: FieldBackend>(constraints: &mut Vec<Constraint<F>>) {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(constraints.len());

    constraints.retain(|c| {
        let fa = lc_fingerprint(&c.a);
        let fb = lc_fingerprint(&c.b);
        let fc = lc_fingerprint(&c.c);

        // Canonical key: sort A,B to handle commutativity (A*B=C ≡ B*A=C)
        let (fa, fb) = if fa <= fb { (fa, fb) } else { (fb, fa) };

        let mut key = Vec::with_capacity(fa.len() + fb.len() + fc.len() + 2);
        key.extend_from_slice(&fa);
        key.push(0xFF); // separator
        key.extend_from_slice(&fb);
        key.push(0xFF);
        key.extend_from_slice(&fc);

        seen.insert(key)
    });
}
