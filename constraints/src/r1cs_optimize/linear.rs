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

/// Run linear constraint elimination to fixpoint.
///
/// Protected variables (ONE + public inputs, indices `0..=num_pub_inputs`)
/// are never substituted away.
///
/// Returns the reduced constraint set, a substitution map (for witness
/// fixup), and optimization statistics.
pub fn optimize_linear<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_linear_with_protected(constraints, num_pub_inputs, &HashSet::new())
}

/// Like `optimize_linear`, but also protects additional variable indices
/// from substitution. Used by O2 to shield decomposition wires during
/// DEDUCE processing so they remain available as simple monomials.
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

        for (idx, constraint) in constraints.iter().enumerate() {
            if let Some((k, other_lc, c_lc)) = is_linear(constraint) {
                // Constraint encodes: k * other_lc = c_lc
                // i.e., c_lc - k * other_lc = 0
                let combined = c_lc - (other_lc * k);

                // Don't solve for a variable already claimed this round
                let mut this_round_protected = round_protected.clone();
                for var_idx in round_subs.keys() {
                    this_round_protected.insert(*var_idx);
                }

                if let Some((var, expr)) =
                    solve_for_variable(combined, &this_round_protected, &var_freq)
                {
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
fn deduplicate_constraints<F: FieldBackend>(constraints: &mut Vec<Constraint<F>>) {
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
