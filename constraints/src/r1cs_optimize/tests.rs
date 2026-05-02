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

    // First constraint: x substituted -> pub
    // Second: 1*pub = pub -> tautological, removed
    // Third: pub*pub = z -> quadratic, kept
    //
    // The cluster-Gauss path absorbs the tautology inside
    // `solve_cluster_linear` (the second linear constraint reduces
    // to an empty row after the first substitution and is dropped
    // before being re-emitted as residual). The greedy path
    // discovers it via `is_trivially_satisfied` after applying
    // substitutions. End state is the same (1 constraint,
    // 1 var eliminated); the `trivial_removed` counter is a
    // bookkeeping detail and not asserted on.
    assert_eq!(stats.constraints_before, 3);
    assert_eq!(stats.constraints_after, 1, "only pub*pub=z should remain");
    assert_eq!(stats.variables_eliminated, 1);
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

// ========================================================================
// Sparse DEDUCE tests
// ========================================================================

/// Two unrelated constraint sets (disjoint variable indices, disjoint
/// monomials) should be processed as two independent clusters by
/// `optimize_o2_sparse`. The resulting constraint count + variable
/// eliminations must equal the dense `optimize_o2` baseline -- the
/// outer-loop scaffolding is shared, so the only path-dependent
/// difference is whether DEDUCE runs at cluster granularity.
#[test]
fn sparse_cluster_isolation_matches_dense() {
    use crate::r1cs_optimize::{optimize_o2, optimize_o2_sparse};

    fn build_two_disjoint_systems() -> ConstraintSystem<memory::Bn254Fr> {
        let mut cs = ConstraintSystem::new();
        // Cluster A: x*y=z; 1*w=z (linear) -- shares variable z so they
        // do interact in O1, but the quadratic monomial set is {(x,y)}
        // alone.
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        let w = cs.alloc_witness();
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
        cs.enforce_equal(make_lc_var(w), make_lc_var(z));

        // Cluster B: a*b=c; 1*d=c -- separate variable indices, separate
        // monomials. Should not interact with cluster A.
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();
        let c = cs.alloc_witness();
        let d = cs.alloc_witness();
        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce_equal(make_lc_var(d), make_lc_var(c));

        cs
    }

    let mut dense = build_two_disjoint_systems().constraints().to_vec();
    let mut sparse = build_two_disjoint_systems().constraints().to_vec();

    let (_, dense_stats) = optimize_o2(&mut dense, 0);
    let (_, sparse_stats) = optimize_o2_sparse(&mut sparse, 0);

    assert_eq!(
        dense_stats.constraints_after, sparse_stats.constraints_after,
        "sparse and dense O2 must agree on final constraint count for disjoint systems"
    );
    assert_eq!(
        dense_stats.variables_eliminated, sparse_stats.variables_eliminated,
        "sparse and dense O2 must agree on eliminations for disjoint systems"
    );
}

/// On a tiny boolean-decomposition system (one constraint per bit, all
/// sharing variable `ONE`), sparse and dense O2 must converge to the
/// same constraint count. Boolean checks are the dominant pattern in
/// Num2Bits-style circuits where the sparse path is expected to behave
/// identically to dense at small scale.
#[test]
fn sparse_matches_dense_on_boolean_decomposition() {
    use crate::r1cs_optimize::{optimize_o2, optimize_o2_sparse};

    fn build_bool_decomp(n_bits: usize) -> ConstraintSystem<memory::Bn254Fr> {
        let mut cs = ConstraintSystem::new();
        let mut bits = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            bits.push(cs.alloc_witness());
        }
        // Each bit b: b * (1 - b) = 0
        for &b in &bits {
            let one_minus_b = LinearCombination::from_variable(Variable::ONE)
                - LinearCombination::from_variable(b);
            cs.enforce(make_lc_var(b), one_minus_b, LinearCombination::zero());
        }
        cs
    }

    for n_bits in [4usize, 8, 12] {
        let mut dense = build_bool_decomp(n_bits).constraints().to_vec();
        let mut sparse = build_bool_decomp(n_bits).constraints().to_vec();

        let (_, dense_stats) = optimize_o2(&mut dense, 0);
        let (_, sparse_stats) = optimize_o2_sparse(&mut sparse, 0);

        assert_eq!(
            dense_stats.constraints_after, sparse_stats.constraints_after,
            "sparse vs dense disagree on bool decomp(n_bits={n_bits})"
        );
    }
}

/// `optimize_o2_sparse` must be a no-op on a fully linear system (no
/// quadratic constraints). The dense path is already a no-op for
/// DEDUCE in this case; sparse must mirror that exactly so we never
/// fabricate constraints out of thin air on degenerate input.
#[test]
fn sparse_o2_no_op_on_linear_system() {
    use crate::r1cs_optimize::optimize_o2_sparse;

    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    cs.enforce_equal(
        make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
        make_lc_var(c),
    );

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_o2_sparse(&mut constraints, cs.num_pub_inputs());

    // O1 alone substitutes c (or one of a,b) and removes the constraint.
    assert_eq!(stats.constraints_after, 0);
    assert_eq!(stats.variables_eliminated, 1);
    assert_eq!(subs.len(), 1);
}

/// A large cluster (above `MAX_CLUSTER_SIZE`) must be skipped without
/// panicking and without losing soundness. The constraints stay in the
/// system unchanged; O1 + decompose around them still runs.
///
/// We construct a synthetic cluster of 400 quadratic constraints that
/// all share one common monomial `x*y` so they end up in the same
/// connected component. After `optimize_o2_sparse`, the constraint
/// count must still bound the system (no spurious deductions), and
/// the original witness must still satisfy what remains.
#[test]
fn sparse_skips_oversized_cluster() {
    use crate::r1cs_optimize::optimize_o2_sparse;

    let mut cs = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();

    // 400 wires z_i, each with x*y = z_i. All 400 constraints share the
    // monomial (x,y), so Union-Find puts them in one cluster of size 400 > 350.
    let mut zs: Vec<Variable> = Vec::with_capacity(400);
    for _ in 0..400 {
        let z = cs.alloc_witness();
        zs.push(z);
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
    }

    let constraints_before = cs.constraints().len();
    let mut constraints = cs.constraints().to_vec();
    let (_subs, stats) = optimize_o2_sparse(&mut constraints, cs.num_pub_inputs());

    // Sanity: optimize_o2_sparse did not crash and did not blow up the
    // constraint count (skip is supposed to be a no-op for the cluster
    // beyond aux-wire bookkeeping that O1 will sweep).
    assert!(
        stats.constraints_after <= constraints_before,
        "skipped cluster must not grow the system"
    );

    // The 400 constraints share monomial (x,y) and only differ in C.
    // O1 sees them all as 1 * <multi-term LC> = 0 after any deduction
    // would be applied; even without deductions, the system stays
    // satisfiable with x=2, y=3, z_i=6.
    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    witness.extend(std::iter::repeat_n(FieldElement::from_u64(6), 400));
    for c in &constraints {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(
            av.mul(&bv),
            cv,
            "skipped cluster: witness must still satisfy"
        );
    }
}

// ========================================================================
// linear_cluster::build_clusters_by_signal -- partition tests
// ========================================================================

/// Two disjoint linear sub-systems must produce two clusters: their
/// variable-index sets do not overlap, so Union-Find never merges them.
#[test]
fn cluster_isolation_disjoint_subsystems() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    // Cluster A: 1 * a = b -- shares no variables with B.
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    cs.enforce_equal(make_lc_var(a), make_lc_var(b));

    // Cluster B: 1 * c = d -- disjoint variable indices vs A.
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();
    cs.enforce_equal(make_lc_var(c), make_lc_var(d));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    assert_eq!(clusters.len(), 2, "expected 2 disjoint clusters");
    assert!(clusters.iter().all(|c| c.len() == 1));
}

/// Three constraints `a-b`, `b-c`, `c-d` share signals transitively.
/// Union-Find must merge them into a single cluster of size 3.
#[test]
fn cluster_transitive_merge() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(a), make_lc_var(b)); // shares b with next
    cs.enforce_equal(make_lc_var(b), make_lc_var(c)); // shares c with next
    cs.enforce_equal(make_lc_var(c), make_lc_var(d));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    assert_eq!(clusters.len(), 1, "transitive merge -> 1 cluster");
    assert_eq!(clusters[0].len(), 3);
    assert_eq!(clusters[0], vec![0, 1, 2]);
}

/// When every signal a constraint touches is in the protected set,
/// the constraint contributes no merging signal and ends up as a
/// singleton. This guards against Union-Find leaking through public
/// inputs / aux wires (which would inflate clusters without enabling
/// any substitution).
#[test]
fn cluster_all_protected_returns_singletons() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_a = cs.alloc_input();
    let pub_b = cs.alloc_input();
    cs.enforce_equal(make_lc_var(pub_a), make_lc_var(pub_b));
    cs.enforce_equal(make_lc_var(pub_a), make_lc_var(pub_b)); // duplicate

    let constraints = cs.constraints().to_vec();
    // Public inputs are protected: indices 0..=2 (ONE + 2 pub inputs).
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // No mergeable signal -> 2 singletons.
    assert_eq!(clusters.len(), 2);
    assert!(clusters.iter().all(|c| c.len() == 1));
}

// ========================================================================
// linear_cluster::solve_cluster_linear -- per-cluster Gauss tests
// ========================================================================

/// A cluster containing a single non-linear (quadratic) constraint must
/// produce no substitutions and emit the constraint as residual. The
/// solver linearises only what `is_linear` accepts.
#[test]
fn cluster_gauss_singleton_no_substitution() {
    use crate::r1cs_optimize::linear_cluster::solve_cluster_linear;
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();
    let z = cs.alloc_witness();
    // x * y = z -- genuinely quadratic, NOT linear.
    cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);

    let (subs, residual) =
        solve_cluster_linear::<memory::Bn254Fr>(constraints.clone(), &protected, &var_freq);

    assert!(subs.is_empty());
    assert_eq!(residual.len(), 1);
}

/// Cluster-Gauss applied to the same chain system as
/// `test_chain_substitution` (1*a=b, 1*b=c, c*c=d) must produce the
/// same final constraint count and a witness-satisfying residual as
/// the greedy path. Specific substitution keys may differ -- we
/// assert structural equivalence, not byte equality.
#[test]
fn cluster_gauss_chain_match_greedy() {
    use crate::r1cs_optimize::linear_cluster::{build_clusters_by_signal, solve_cluster_linear};
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(a), make_lc_var(b));
    cs.enforce_equal(make_lc_var(b), make_lc_var(c));
    cs.enforce(make_lc_var(c), make_lc_var(c), make_lc_var(d));

    let constraints: Vec<_> = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // Linear constraints (idx 0,1) cluster together via shared variable b.
    // Quadratic constraint (idx 2) is its own singleton (is_linear -> None).
    // Solve only the linear cluster.
    let mut total_subs = std::collections::HashMap::new();
    let mut total_residual: Vec<Constraint<memory::Bn254Fr>> = Vec::new();
    for cluster in &clusters {
        let cluster_cons: Vec<_> = cluster.iter().map(|i| constraints[*i].clone()).collect();
        let (subs, residual) =
            solve_cluster_linear::<memory::Bn254Fr>(cluster_cons, &protected, &var_freq);
        total_subs.extend(subs);
        total_residual.extend(residual);
    }

    // Greedy variant eliminated 2 vars and left 1 quadratic; cluster-Gauss
    // must match those counts.
    assert_eq!(
        total_subs.len(),
        2,
        "expected 2 vars eliminated (a and b OR b and c)"
    );
    assert_eq!(total_residual.len(), 1, "1 quadratic residual constraint");

    // Witness check: a=b=c=5, d=25 satisfies the residual quadratic.
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(5),  // a
        FieldElement::from_u64(5),  // b
        FieldElement::from_u64(5),  // c
        FieldElement::from_u64(25), // d
    ];
    let con = &total_residual[0];
    let av = con.a.evaluate(&witness).unwrap();
    let bv = con.b.evaluate(&witness).unwrap();
    let cv = con.c.evaluate(&witness).unwrap();
    assert_eq!(av.mul(&bv), cv);
}

// ========================================================================
// optimize_linear_clustered driver tests
// ========================================================================

/// Mirror of `test_single_linear_elimination` (the very first sanity
/// test for greedy O1) under the clustered driver. Same input, same
/// expected outcome: one substitution, one quadratic constraint left,
/// witness still satisfied.
#[test]
fn cluster_gauss_multi_cluster_correctness() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();
    let z = cs.alloc_witness();
    let w = cs.alloc_witness();

    // x * y = z (quadratic, kept)
    cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
    // 1 * w = z  (linear: w = z)
    cs.enforce_equal(make_lc_var(w), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.constraints_before, 2);
    assert_eq!(stats.constraints_after, 1);
    assert_eq!(stats.variables_eliminated, 1);
    assert_eq!(subs.len(), 1);

    // Witness check: x=6, y=7, z=42, w=42
    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(6),  // x
        FieldElement::from_u64(7),  // y
        FieldElement::from_u64(42), // z
        FieldElement::from_u64(42), // w
    ];
    for (var_idx, lc) in &subs {
        witness[*var_idx] = lc.evaluate(&witness).unwrap();
    }
    for c in &constraints {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(av.mul(&bv), cv);
    }
}

/// `extra_protected` plumbing: a synthetic "aux wire" shared with a
/// non-protected variable across a cluster must never be picked as
/// the substitution target -- the picker (max-frequency or min-occ)
/// must always pick the non-protected wire.
#[test]
fn cluster_gauss_aux_wire_protection() {
    use crate::r1cs_optimize::linear_cluster::optimize_linear_clustered_with_protected;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let aux = cs.alloc_witness(); // pretend this is a decompose aux wire (idx 1)
    let other = cs.alloc_witness(); // idx 2

    // 1 * aux = other -- linear, picker chooses one of {aux, other}.
    cs.enforce_equal(make_lc_var(aux), make_lc_var(other));

    let mut constraints = cs.constraints().to_vec();
    let mut extra: HashSet<usize> = HashSet::new();
    extra.insert(aux.index());
    let (subs, _stats) =
        optimize_linear_clustered_with_protected(&mut constraints, cs.num_pub_inputs(), &extra);

    assert!(
        !subs.contains_key(&aux.index()),
        "aux wire must NOT be substituted"
    );
    assert!(
        subs.contains_key(&other.index()),
        "other wire SHOULD be substituted"
    );
}

/// Public input variables must never be substituted. Mirrors
/// `test_public_variable_not_substituted` for the clustered driver.
#[test]
fn cluster_gauss_does_not_substitute_protected() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input(); // idx 1, public
    let w = cs.alloc_witness(); // idx 2
    let z = cs.alloc_witness(); // idx 3

    cs.enforce_equal(make_lc_var(pub_out), make_lc_var(w));
    cs.enforce(make_lc_var(w), make_lc_var(w), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 1);
    assert!(subs.contains_key(&w.index()), "w should be substituted");
    assert!(!subs.contains_key(&pub_out.index()), "pub_out is protected");
    assert_eq!(constraints.len(), 1, "only the quadratic should remain");
}

/// Larger end-to-end soundness check on the `test_optimization_preserves_satisfaction`
/// system, run through the clustered driver. After fixup, every
/// remaining constraint must still satisfy the witness.
#[test]
fn cluster_gauss_soundness_witness_roundtrip() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let m1 = cs.alloc_witness();
    let m2 = cs.alloc_witness();
    let c = cs.alloc_witness();

    cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(pub_out));
    cs.enforce_equal(
        make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
        make_lc_var(m1),
    );
    cs.enforce(make_lc_var(m1), make_lc_var(a), make_lc_var(m2));
    cs.enforce_equal(make_lc_var(m2), make_lc_var(c));

    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(12), // pub_out
        FieldElement::from_u64(3),  // a
        FieldElement::from_u64(4),  // b
        FieldElement::from_u64(7),  // m1 = a+b
        FieldElement::from_u64(21), // m2 = m1*a
        FieldElement::from_u64(21), // c = m2
    ];

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());
    assert_eq!(stats.constraints_before, 4);
    assert_eq!(stats.constraints_after, 2);

    // Apply subs to witness.
    for (var_idx, lc) in &subs {
        witness[*var_idx] = lc.evaluate(&witness).unwrap();
    }

    for (i, c) in constraints.iter().enumerate() {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(
            av.mul(&bv),
            cv,
            "constraint {i} unsatisfied after clustered optimization"
        );
    }
}

/// Substituting one side of a constraint can collapse it into a
/// tautology (e.g. `1 * pub = pub` after `x = pub`). The clustered
/// driver must remove those via the trivial sweep.
#[test]
fn cluster_gauss_tautology_after_pivot() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input(); // idx 1
    let x = cs.alloc_witness(); // idx 2
    let z = cs.alloc_witness(); // idx 3

    cs.enforce_equal(make_lc_var(pub_out), make_lc_var(x));
    cs.enforce_equal(make_lc_var(x), make_lc_var(pub_out));
    cs.enforce(make_lc_var(x), make_lc_var(x), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    // Cluster-Gauss absorbs the tautology inside solve_cluster_linear
    // (the second linear constraint reduces to an empty row after the
    // first substitution and is dropped before being re-emitted as
    // residual), whereas the greedy path discovers it via
    // is_trivially_satisfied AFTER applying substitutions. Both
    // arrive at the same end state (1 constraint left, 1 var
    // eliminated) by different bookkeeping; we assert the end state.
    assert_eq!(stats.constraints_before, 3);
    assert_eq!(
        stats.constraints_after, 1,
        "only pub*pub=z should remain after tautology absorption"
    );
    assert_eq!(stats.variables_eliminated, 1);
}

// ========================================================================
// Picker selection tests
// ========================================================================

/// Above the MIN_OCCURRENCE_LOWER threshold (350), the picker switches
/// to min-occurrence: the variable with the FEWEST occurrences in the
/// global frequency map wins, tie-broken by largest signal index.
///
/// Construction: 360 linear constraints `1 * hot = bot_i` for
/// i in 0..360. `hot` (idx 1) appears in 360 rows; each `bot_i`
/// (indices 2..362) appears in exactly 1 row. They form one cluster
/// of 360 (above the threshold).
///
/// Under min-occurrence: every row picks its own `bot_i` (freq 1)
/// over `hot` (freq 360). Result: subs = {bot_0..bot_359}, hot is
/// NEVER substituted.
#[test]
fn cluster_gauss_min_occurrence_picker_above_threshold() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let hot = cs.alloc_witness();
    let mut bots: Vec<Variable> = Vec::with_capacity(360);
    for _ in 0..360 {
        bots.push(cs.alloc_witness());
    }
    for &b in &bots {
        cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
    }

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 360);
    assert!(
        !subs.contains_key(&hot.index()),
        "hot variable (idx {}) must NOT be substituted under min-occurrence picker; \
         subs has {} keys, hot present={}",
        hot.index(),
        subs.len(),
        subs.contains_key(&hot.index()),
    );
    // Every bot_i should be substituted instead.
    for &b in &bots {
        assert!(
            subs.contains_key(&b.index()),
            "bot variable (idx {}) should be substituted",
            b.index()
        );
    }
}

/// Below the threshold (340 < 350), the picker stays max-frequency:
/// `hot` (freq 340) wins over each `bot_i` (freq 1). Hot IS
/// substituted in the first round.
#[test]
fn cluster_gauss_max_frequency_picker_below_threshold() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let hot = cs.alloc_witness();
    let mut bots: Vec<Variable> = Vec::with_capacity(340);
    for _ in 0..340 {
        bots.push(cs.alloc_witness());
    }
    for &b in &bots {
        cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
    }

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 340);
    // Under max-frequency, the FIRST row's pick is `hot` -> hot is
    // in subs. (Other bot_i's get substituted in subsequent rows.)
    assert!(
        subs.contains_key(&hot.index()),
        "hot variable (idx {}) MUST be substituted under max-frequency picker",
        hot.index(),
    );
}

/// Threshold boundary: exactly 350 triggers min-occurrence; 349 stays
/// max-frequency. Documents the picker's branch condition.
#[test]
fn cluster_gauss_picker_threshold_exact() {
    use crate::r1cs_optimize::optimize_linear;

    fn build_and_optimize(n: usize) -> bool {
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let hot = cs.alloc_witness();
        let mut bots: Vec<Variable> = Vec::with_capacity(n);
        for _ in 0..n {
            bots.push(cs.alloc_witness());
        }
        for &b in &bots {
            cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
        }
        let mut constraints = cs.constraints().to_vec();
        let (subs, _stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());
        // Returns true iff hot was substituted (max-frequency picker).
        subs.contains_key(&hot.index())
    }

    // 349 -> max-frequency -> hot substituted -> returns true
    assert!(
        build_and_optimize(349),
        "n=349 should use max-frequency (hot substituted)"
    );
    // 350 -> min-occurrence -> hot NOT substituted -> returns false
    assert!(
        !build_and_optimize(350),
        "n=350 should use min-occurrence (hot NOT substituted)"
    );
}

/// 20 linear constraints all sharing one anchor variable (a) collapse
/// completely under cluster-Gauss: 20 substitutions produced, no
/// duplicates in the substitution map, residual empty.
#[test]
fn cluster_gauss_high_degree_variable() {
    use crate::r1cs_optimize::linear_cluster::{build_clusters_by_signal, solve_cluster_linear};
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let mut bs: Vec<Variable> = Vec::with_capacity(20);
    for _ in 0..20 {
        bs.push(cs.alloc_witness());
    }
    // 20 constraints: a == b_i for i in 0..20.
    for &b in &bs {
        cs.enforce_equal(make_lc_var(a), make_lc_var(b));
    }

    let constraints: Vec<_> = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // All 20 constraints share variable `a` -- one cluster of 20.
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].len(), 20);

    let cluster_cons: Vec<_> = clusters[0]
        .iter()
        .map(|i| constraints[*i].clone())
        .collect();
    let (subs, residual) =
        solve_cluster_linear::<memory::Bn254Fr>(cluster_cons, &protected, &var_freq);

    // 20 linear constraints over 21 variables (a + b0..b19) collapse
    // to 20 substitutions; the surviving variable is the one each
    // substitution chains to.
    assert_eq!(subs.len(), 20);
    assert!(
        residual.is_empty(),
        "residual should be empty, got {residual:?}"
    );

    // No substitution should reference itself (acyclic invariant).
    for (var_idx, expr) in &subs {
        for (term_var, _) in expr.terms() {
            assert_ne!(term_var.index(), *var_idx, "self-reference in subs map");
        }
    }
}
