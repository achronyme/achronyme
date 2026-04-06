//! R1CS Linear Constraint Elimination
//!
//! Identifies constraints of the form `k * LC_a = LC_b` (where k is a nonzero
//! constant) and substitutes one variable away, eliminating the constraint.
//! Runs to fixpoint — each round may expose new linear constraints.
//!
//! This is the R1CS analogue of circom's `--O1` simplification pass.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Statistics from linear constraint elimination.
#[derive(Debug, Clone)]
pub struct R1CSOptimizeResult {
    /// Number of constraints before optimization.
    pub constraints_before: usize,
    /// Number of constraints after optimization.
    pub constraints_after: usize,
    /// Number of variables substituted away.
    pub variables_eliminated: usize,
    /// Number of duplicate non-linear constraints removed.
    pub duplicates_removed: usize,
}

/// Maps a variable index to the LC that replaces it.
pub type SubstitutionMap<F> = HashMap<usize, LinearCombination<F>>;

/// Apply all substitutions in `subs` to a linear combination.
///
/// For each term `(var, coeff)` in `lc`: if `var` is in `subs`, replace the
/// term with `coeff * subs[var]`. Returns the simplified result.
fn apply_substitution<F: FieldBackend>(
    lc: &LinearCombination<F>,
    subs: &SubstitutionMap<F>,
) -> LinearCombination<F> {
    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &lc.terms {
        if let Some(replacement) = subs.get(&var.index()) {
            // var -> replacement LC, scaled by coeff
            result = result + replacement.clone() * *coeff;
        } else {
            result.add_term(*var, *coeff);
        }
    }
    result.simplify()
}

/// Apply substitutions to all three LCs in a constraint.
fn apply_substitution_to_constraint<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> Constraint<F> {
    Constraint {
        a: apply_substitution(&constraint.a, subs),
        b: apply_substitution(&constraint.b, subs),
        c: apply_substitution(&constraint.c, subs),
    }
}

/// Check if a constraint is linear (one side is a constant).
///
/// Returns `Some((constant_value, other_lc, c_lc))` where the constraint
/// encodes `constant * other_lc = c_lc`. Returns `None` if both A and B
/// contain variables (genuinely quadratic).
fn is_linear<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> Option<(FieldElement<F>, LinearCombination<F>, LinearCombination<F>)> {
    let a_simplified = constraint.a.simplify();
    if let Some(k) = a_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.b.simplify(), constraint.c.simplify()));
        }
    }
    let b_simplified = constraint.b.simplify();
    if let Some(k) = b_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.a.simplify(), constraint.c.simplify()));
        }
    }
    None
}

/// Given an LC that must equal zero, solve for a non-protected variable.
///
/// E.g., for `3*x + 2*y - z + 5*ONE = 0`, solving for z gives:
/// `z = 3*x + 2*y + 5*ONE`.
///
/// Prefers the variable with the highest index (most likely to be an
/// intermediate wire, not an input).
fn solve_for_variable<F: FieldBackend>(
    lc: LinearCombination<F>,
    protected: &HashSet<usize>,
) -> Option<(Variable, LinearCombination<F>)> {
    let simplified = lc.simplify();

    // Find the best candidate: highest-index non-protected variable
    let mut best: Option<(Variable, FieldElement<F>)> = None;
    for (var, coeff) in &simplified.terms {
        if protected.contains(&var.index()) {
            continue;
        }
        if var.index() == 0 {
            continue; // Never substitute Variable::ONE
        }
        match &best {
            None => best = Some((*var, *coeff)),
            Some((prev_var, _)) => {
                if var.index() > prev_var.index() {
                    best = Some((*var, *coeff));
                }
            }
        }
    }

    let (target_var, target_coeff) = best?;

    // We need to compute: target_var = (-1/target_coeff) * (all other terms)
    let neg_inv = target_coeff.neg().inv()?;

    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &simplified.terms {
        if *var == target_var {
            continue;
        }
        result.add_term(*var, coeff.mul(&neg_inv));
    }

    Some((target_var, result))
}

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
    let constraints_before = constraints.len();

    // Protected: ONE (0) + public inputs (1..=num_pub_inputs)
    let protected: HashSet<usize> = (0..=num_pub_inputs).collect();

    let mut all_subs: SubstitutionMap<F> = HashMap::new();

    loop {
        let mut round_subs: SubstitutionMap<F> = HashMap::new();
        let mut to_remove: HashSet<usize> = HashSet::new();

        // Also protect variables already substituted in previous rounds
        let mut round_protected = protected.clone();
        for var_idx in all_subs.keys() {
            round_protected.insert(*var_idx);
        }

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

                if let Some((var, expr)) = solve_for_variable(combined, &this_round_protected) {
                    round_subs.insert(var.index(), expr);
                    to_remove.insert(idx);
                }
            }
        }

        if round_subs.is_empty() {
            break;
        }

        // Remove eliminated constraints and apply substitutions to the rest
        *constraints = constraints
            .iter()
            .enumerate()
            .filter(|(idx, _)| !to_remove.contains(idx))
            .map(|(_, c)| apply_substitution_to_constraint(c, &round_subs))
            .collect();

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

    let result = R1CSOptimizeResult {
        constraints_before,
        constraints_after: constraints.len(),
        variables_eliminated: all_subs.len(),
        duplicates_removed,
    };

    (all_subs, result)
}

/// Hash a simplified linear combination into a deterministic byte vector.
fn lc_fingerprint<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<u8> {
    let simplified = lc.simplify();
    let mut bytes = Vec::with_capacity(simplified.terms.len() * 40);
    for (var, coeff) in &simplified.terms {
        bytes.extend_from_slice(&var.index().to_le_bytes());
        for limb in coeff.to_canonical().iter() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

/// Remove duplicate constraints (same A, B, C after simplification).
/// Also removes commuted duplicates (A*B=C == B*A=C).
fn deduplicate_constraints<F: FieldBackend>(constraints: &mut Vec<Constraint<F>>) {
    use std::collections::HashSet;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::ConstraintSystem;
    use memory::FieldElement;

    /// Helper: build a constraint system, optimize it, and verify.
    fn make_lc_var<F: FieldBackend>(var: Variable) -> LinearCombination<F> {
        LinearCombination::from_variable(var)
    }
    fn make_lc_const<F: FieldBackend>(val: u64) -> LinearCombination<F> {
        LinearCombination::from_constant(FieldElement::from_u64(val))
    }

    // ========================================================================
    // Test 1: Single linear constraint elimination
    // ========================================================================
    #[test]
    fn test_single_linear_elimination() {
        // System: x * y = z (quadratic, kept)
        //         1 * w = z (linear: w = z, eliminate)
        let mut cs = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3
        let w = cs.alloc_witness(); // 4

        // x * y = z
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
        // 1 * w = z  (i.e. w = z)
        cs.enforce_equal(make_lc_var(w), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 1);
        // w (idx 4) should be substituted
        assert!(subs.contains_key(&4));

        // Remaining constraint should still be satisfiable
        // After substitution, w is replaced by z everywhere
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(6),  // x
            FieldElement::from_u64(7),  // y
            FieldElement::from_u64(42), // z = x*y
            FieldElement::from_u64(42), // w = z
        ];
        for c in &constraints {
            let a_val = c.a.evaluate(&witness).unwrap();
            let b_val = c.b.evaluate(&witness).unwrap();
            let c_val = c.c.evaluate(&witness).unwrap();
            assert_eq!(a_val.mul(&b_val), c_val);
        }
    }

    // ========================================================================
    // Test 2: Constant propagation
    // ========================================================================
    #[test]
    fn test_constant_propagation() {
        // System: 1 * x = 5*ONE  (x = 5, constant)
        //         x * y = z      (after sub x=5: 5*ONE * y = z, also linear → z = 5y)
        // Both constraints are fully linear after propagation → 0 remaining.
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let _z = cs.alloc_witness(); // 3

        // x = 5
        cs.enforce_equal(make_lc_var(x), make_lc_const(5));
        // x * y = z
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(_z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // x=5 makes the second constraint linear (5*y = z), so z is also eliminated
        assert_eq!(stats.constraints_after, 0);
        assert_eq!(stats.variables_eliminated, 2);
        assert!(subs.contains_key(&1)); // x substituted with constant 5
        assert!(subs.contains_key(&3)); // z substituted with 5*y
    }

    // ========================================================================
    // Test 3: Public variable protection
    // ========================================================================
    #[test]
    fn test_public_variable_not_substituted() {
        // System: 1 * pub_out = w  (linear, but pub_out is public — can't sub it)
        //         w * w = z        (quadratic)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let pub_out = cs.alloc_input(); // 1 (public)
        let w = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3

        // pub_out = w  (linear)
        cs.enforce_equal(make_lc_var(pub_out), make_lc_var(w));
        // w * w = z
        cs.enforce(make_lc_var(w), make_lc_var(w), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // w (idx 2) should be substituted, NOT pub_out (idx 1)
        assert_eq!(stats.variables_eliminated, 1);
        assert!(subs.contains_key(&2)); // w substituted
        assert!(!subs.contains_key(&1)); // pub_out protected

        // After optimization: w is replaced by pub_out
        // Remaining constraints: pub_out * pub_out = z
        assert_eq!(constraints.len(), 1);
    }

    // ========================================================================
    // Test 4: Chain substitution (fixpoint)
    // ========================================================================
    #[test]
    fn test_chain_substitution() {
        // System: 1 * a = b   (a = b)
        //         1 * b = c   (b = c)
        //         c * c = d   (quadratic)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let d = cs.alloc_witness(); // 4

        cs.enforce_equal(make_lc_var(a), make_lc_var(b));
        cs.enforce_equal(make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(c), make_lc_var(d));

        let mut constraints = cs.constraints().to_vec();
        let (_subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Both linear constraints eliminated
        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 2);

        // a and b should both resolve to c (or chain: a->b->c)
        // Verify the remaining constraint is satisfiable
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(5),  // a
            FieldElement::from_u64(5),  // b
            FieldElement::from_u64(5),  // c
            FieldElement::from_u64(25), // d = c^2
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 5: Mixed linear and nonlinear
    // ========================================================================
    #[test]
    fn test_mixed_linear_nonlinear() {
        // System: a * b = c  (quadratic, kept)
        //         c * d = e  (quadratic, kept)
        //         1 * f = e  (linear, eliminated)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let d = cs.alloc_witness(); // 4
        let e = cs.alloc_witness(); // 5
        let f = cs.alloc_witness(); // 6

        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(d), make_lc_var(e));
        cs.enforce_equal(make_lc_var(f), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 2);
        assert_eq!(stats.variables_eliminated, 1);
    }

    // ========================================================================
    // Test 6: Empty system
    // ========================================================================
    #[test]
    fn test_empty_system() {
        let mut constraints: Vec<Constraint> = vec![];
        let (subs, stats) = optimize_linear(&mut constraints, 0);

        assert_eq!(stats.constraints_before, 0);
        assert_eq!(stats.constraints_after, 0);
        assert_eq!(stats.variables_eliminated, 0);
        assert!(subs.is_empty());
    }

    // ========================================================================
    // Test 7: Already optimal (only multiplications)
    // ========================================================================
    #[test]
    fn test_already_optimal() {
        // System: a * b = c (all quadratic)
        //         c * d = e
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();
        let c = cs.alloc_witness();
        let d = cs.alloc_witness();
        let e = cs.alloc_witness();

        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 2);
        assert_eq!(stats.variables_eliminated, 0);
        assert!(subs.is_empty());
    }

    // ========================================================================
    // Test 8: Materialization pattern (the main source of bloat)
    // ========================================================================
    #[test]
    fn test_materialize_pattern() {
        // Simulates what auto_materialize generates:
        // 1 * (a + b + c) = m   (materialization: m = a+b+c)
        // m * d = e              (actual multiplication)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let m = cs.alloc_witness(); // 4 (materialized)
        let d = cs.alloc_witness(); // 5
        let e = cs.alloc_witness(); // 6

        // materialization: (a+b+c) * 1 = m
        let mut sum = LinearCombination::zero();
        sum.add_term(a, FieldElement::ONE);
        sum.add_term(b, FieldElement::ONE);
        sum.add_term(c, FieldElement::ONE);
        cs.enforce_equal(sum, make_lc_var(m));

        // actual mul: m * d = e
        cs.enforce(make_lc_var(m), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Materialization constraint should be eliminated
        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert!(subs.contains_key(&4)); // m substituted with a+b+c

        // Remaining constraint: (a+b+c) * d = e
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(2),  // a
            FieldElement::from_u64(3),  // b
            FieldElement::from_u64(5),  // c
            FieldElement::from_u64(10), // m = a+b+c = 10
            FieldElement::from_u64(4),  // d
            FieldElement::from_u64(40), // e = (a+b+c)*d = 40
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 9: Scaled linear constraint (k != 1)
    // ========================================================================
    #[test]
    fn test_scaled_linear() {
        // System: 3 * x = y  (i.e., y = 3x)
        //         y * y = z
        let mut cs = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3

        // 3*ONE * x = y
        cs.enforce(make_lc_const(3), make_lc_var(x), make_lc_var(y));
        // y * y = z
        cs.enforce(make_lc_var(y), make_lc_var(y), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 1);
        assert!(subs.contains_key(&2)); // y substituted with 3*x

        // Verify: x=4, y=12, z=144
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(4),   // x
            FieldElement::from_u64(12),  // y = 3*4
            FieldElement::from_u64(144), // z = 12*12
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 10: Boolean enforcement is NOT eliminated
    // ========================================================================
    #[test]
    fn test_boolean_enforcement_kept() {
        // Boolean: v * (1 - v) = 0
        // This is NOT linear (both A and B contain variable v)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let v = cs.alloc_witness(); // 1

        // v * (1 - v) = 0
        let one_minus_v =
            LinearCombination::from_variable(Variable::ONE) - LinearCombination::from_variable(v);
        cs.enforce(make_lc_var(v), one_minus_v, LinearCombination::zero());

        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Should NOT be eliminated — both A and B have variables
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 0);
    }

    // ========================================================================
    // Test 11: Multiple materializations in chain
    // ========================================================================
    #[test]
    fn test_multiple_materializations() {
        // Simulates a chain of additions that auto_materialize would produce:
        // m1 = a + b        (linear)
        // m2 = m1 + c       (linear)
        // m2 * d = e        (quadratic)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let m1 = cs.alloc_witness(); // 4
        let m2 = cs.alloc_witness(); // 5
        let d = cs.alloc_witness(); // 6
        let e = cs.alloc_witness(); // 7

        // m1 = a + b
        let ab = make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b);
        cs.enforce_equal(ab, make_lc_var(m1));
        // m2 = m1 + c
        let m1c = make_lc_var::<memory::Bn254Fr>(m1) + make_lc_var(c);
        cs.enforce_equal(m1c, make_lc_var(m2));
        // m2 * d = e
        cs.enforce(make_lc_var(m2), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Both materializations eliminated (may take 2 rounds for chain)
        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 1);
        assert!(subs.contains_key(&4) || subs.contains_key(&5));

        // Final constraint should be: (a+b+c) * d = e
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(1),  // a
            FieldElement::from_u64(2),  // b
            FieldElement::from_u64(3),  // c
            FieldElement::from_u64(3),  // m1 = a+b
            FieldElement::from_u64(6),  // m2 = m1+c
            FieldElement::from_u64(4),  // d
            FieldElement::from_u64(24), // e = 6*4
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 12: Verify optimization preserves witness satisfaction
    // ========================================================================
    #[test]
    fn test_optimization_preserves_satisfaction() {
        // Build a realistic mini-circuit:
        //   pub_out = a * b        (quadratic)
        //   m1 = a + b             (materialization)
        //   m2 = m1 * a            (quadratic, uses materialized wire)
        //   assert m2 = c          (linear: m2 = c)
        let mut cs = ConstraintSystem::new();
        let pub_out = cs.alloc_input(); // 1
        let a = cs.alloc_witness(); // 2
        let b = cs.alloc_witness(); // 3
        let m1 = cs.alloc_witness(); // 4
        let m2 = cs.alloc_witness(); // 5 (= m1 * a)
        let c = cs.alloc_witness(); // 6

        // pub_out = a * b
        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(pub_out));
        // m1 = a + b (materialization)
        cs.enforce_equal(
            make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
            make_lc_var(m1),
        );
        // m2 = m1 * a
        cs.enforce(make_lc_var(m1), make_lc_var(a), make_lc_var(m2));
        // m2 = c (assert)
        cs.enforce_equal(make_lc_var(m2), make_lc_var(c));

        // a=3, b=4: pub_out=12, m1=7, m2=21, c=21
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(12), // pub_out
            FieldElement::from_u64(3),  // a
            FieldElement::from_u64(4),  // b
            FieldElement::from_u64(7),  // m1 = a+b
            FieldElement::from_u64(21), // m2 = m1*a
            FieldElement::from_u64(21), // c = m2
        ];

        // Verify before optimization
        assert!(cs.verify(&witness).is_ok());

        // Optimize
        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Should eliminate the 2 linear constraints (m1 materialization + m2=c assert)
        assert_eq!(stats.constraints_before, 4);
        assert_eq!(stats.constraints_after, 2);

        // Verify after optimization
        for (i, con) in constraints.iter().enumerate() {
            let a_val = con.a.evaluate(&witness).unwrap();
            let b_val = con.b.evaluate(&witness).unwrap();
            let c_val = con.c.evaluate(&witness).unwrap();
            assert_eq!(
                a_val.mul(&b_val),
                c_val,
                "constraint {i} unsatisfied after optimization"
            );
        }
    }
}
