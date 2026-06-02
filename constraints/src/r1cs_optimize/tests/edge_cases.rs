use super::super::predicates::is_trivially_satisfied;
use super::super::*;
use super::make_lc_var;
use crate::r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;

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
