use super::predicates::is_trivially_satisfied;
use super::*;
use crate::r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable};
use memory::{FieldBackend, FieldElement};

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
    // Frequency heuristic: z (idx 3, freq=2) preferred over w (idx 4, freq=1)
    assert!(subs.contains_key(&3) || subs.contains_key(&4));

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

// ========================================================================
// Test 13: Tautological linear constraints are removed
// ========================================================================
#[test]
fn test_tautological_linear_removed() {
    // Directly test is_trivially_satisfied on a tautological constraint:
    // 1 * (3x + 5y) = (3x + 5y) → always satisfied
    let x = Variable(1);
    let y = Variable(2);

    let mut lc = LinearCombination::<memory::Bn254Fr>::zero();
    lc.add_term(x, FieldElement::from_u64(3));
    lc.add_term(y, FieldElement::from_u64(5));

    let taut = Constraint {
        a: LinearCombination::from_variable(Variable::ONE),
        b: lc.clone(),
        c: lc,
    };
    assert!(is_trivially_satisfied(&taut));

    // Non-tautological: 1 * (3x + 5y) = (3x + 7y)
    let mut c2 = LinearCombination::<memory::Bn254Fr>::zero();
    c2.add_term(x, FieldElement::from_u64(3));
    c2.add_term(y, FieldElement::from_u64(7));
    let non_taut = Constraint {
        a: LinearCombination::from_variable(Variable::ONE),
        b: {
            let mut b = LinearCombination::zero();
            b.add_term(x, FieldElement::from_u64(3));
            b.add_term(y, FieldElement::from_u64(5));
            b
        },
        c: c2,
    };
    assert!(!is_trivially_satisfied(&non_taut));

    // Tautological after substitution with protected variables:
    // System: 1 * pub = x       (linear: x = pub, sub x → pub)
    //         1 * x = pub       (after sub: 1*pub = pub → tautological!)
    //         x * x = z         (after sub: pub*pub = z, quadratic, kept)
    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input(); // 1 (protected)
    let x_var = cs.alloc_witness(); // 2
    let z_var = cs.alloc_witness(); // 3

    cs.enforce_equal(make_lc_var(pub_out), make_lc_var(x_var));
    cs.enforce_equal(make_lc_var(x_var), make_lc_var(pub_out));
    cs.enforce(make_lc_var(x_var), make_lc_var(x_var), make_lc_var(z_var));

    let mut constraints = cs.constraints().to_vec();
    let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    // First constraint: x substituted → pub
    // Second: 1*pub = pub → tautological, removed
    // Third: pub*pub = z → quadratic, kept
    assert_eq!(stats.constraints_before, 3);
    assert_eq!(stats.constraints_after, 1, "only pub*pub=z should remain");
    assert!(
        stats.trivial_removed >= 1,
        "tautological constraint detected"
    );
}

// ========================================================================
// Test 14: Zero-product constraint (0 * B = C) handled
// ========================================================================
#[test]
fn test_zero_product_constraint() {
    // System: x * y = z     (quadratic)
    //         0 * w = v     (zero-product: v = 0, eliminable)
    //         v * v = out   (after sub v→0: 0*0=out → trivial if out=0)
    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness(); // 1
    let y = cs.alloc_witness(); // 2
    let z = cs.alloc_witness(); // 3
    let w = cs.alloc_witness(); // 4
    let v = cs.alloc_witness(); // 5
    let out = cs.alloc_witness(); // 6

    cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
    // 0 * w = v
    cs.enforce(LinearCombination::zero(), make_lc_var(w), make_lc_var(v));
    cs.enforce(make_lc_var(v), make_lc_var(v), make_lc_var(out));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    // v should be substituted to 0 (from zero-product constraint)
    // Then v*v=out becomes 0*0=out, where out gets substituted to 0 too
    assert!(subs.contains_key(&5) || subs.contains_key(&6)); // v or out substituted
    assert!(stats.constraints_after <= 2); // at most x*y=z + maybe one more

    // Verify
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(6),  // x
        FieldElement::from_u64(7),  // y
        FieldElement::from_u64(42), // z
        FieldElement::from_u64(99), // w (unconstrained after opt)
        FieldElement::from_u64(0),  // v = 0
        FieldElement::from_u64(0),  // out = 0
    ];
    for c in &constraints {
        let a_val = c.a.evaluate(&witness).unwrap();
        let b_val = c.b.evaluate(&witness).unwrap();
        let c_val = c.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }
}

// ========================================================================
// Test 15: Frequency heuristic picks most-connected variable
// ========================================================================
#[test]
fn test_frequency_heuristic() {
    // Frequency heuristic: substitute the variable that appears in the
    // MOST constraints, to maximize propagation.
    //
    // In constraint `c - a - b = 0`:
    //   a (idx 1): freq=3 (in constraints 1,2,3)
    //   b (idx 2): freq=1 (in constraint 1 only)
    //   c (idx 3): freq=1 (in constraint 1 only)
    // Highest-freq = a → substitute a = c - b
    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness(); // 1
    let b = cs.alloc_witness(); // 2
    let c = cs.alloc_witness(); // 3
    let d = cs.alloc_witness(); // 4
    let e = cs.alloc_witness(); // 5
    let f = cs.alloc_witness(); // 6
    let g = cs.alloc_witness(); // 7

    cs.enforce_equal(
        make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
        make_lc_var(c),
    );
    cs.enforce(make_lc_var(a), make_lc_var(d), make_lc_var(e));
    cs.enforce(make_lc_var(a), make_lc_var(f), make_lc_var(g));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.constraints_before, 3);
    assert_eq!(stats.constraints_after, 2);
    assert_eq!(stats.variables_eliminated, 1);
    // a (idx 1) should be substituted (highest frequency = 3)
    assert!(
        subs.contains_key(&1),
        "expected a (idx 1) to be substituted (highest freq)"
    );
}
