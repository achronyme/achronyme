use super::*;
use memory::FieldElement;

#[test]
fn test_simple_multiplication_constraint() {
    // Circuit: prove knowledge of a, b such that a * b = c (public)
    let mut cs: ConstraintSystem = ConstraintSystem::new();

    // Public output
    let c = cs.alloc_input(); // index 1

    // Private inputs
    let a = cs.alloc_witness(); // index 2
    let b = cs.alloc_witness(); // index 3

    // Constraint: a * b = c
    cs.enforce(
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(c),
    );

    assert_eq!(cs.num_variables(), 4); // ONE, c, a, b
    assert_eq!(cs.num_pub_inputs(), 1); // c
    assert_eq!(cs.num_constraints(), 1);

    // Witness: ONE=1, c=42, a=6, b=7
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(42), // c
        FieldElement::from_u64(6),  // a
        FieldElement::from_u64(7),  // b
    ];

    assert!(cs.verify(&witness).is_ok());
}

#[test]
fn test_failing_constraint() {
    let mut cs = ConstraintSystem::new();
    let c = cs.alloc_input();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();

    cs.enforce(
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(c),
    );

    // Wrong witness: 6 * 7 != 43
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(43), // wrong c
        FieldElement::from_u64(6),
        FieldElement::from_u64(7),
    ];

    assert_eq!(
        cs.verify(&witness),
        Err(ConstraintError::ConstraintUnsatisfied(0))
    );
}

#[test]
fn test_linear_combination_evaluate() {
    // LC: 3*x + 5*y
    let x = Variable(1);
    let y = Variable(2);

    let mut lc = LinearCombination::zero();
    lc.add_term(x, FieldElement::from_u64(3));
    lc.add_term(y, FieldElement::from_u64(5));

    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(10), // x = 10
        FieldElement::from_u64(4),  // y = 4
    ];

    // 3*10 + 5*4 = 50
    assert_eq!(lc.evaluate(&witness).unwrap(), FieldElement::from_u64(50));
}

#[test]
fn linear_combination_fast_shape_queries_match_simplified_semantics() {
    let zero: LinearCombination = LinearCombination::zero();
    assert!(zero.is_constant());
    assert_eq!(zero.constant_value(), Some(FieldElement::zero()));
    assert_eq!(zero.as_single_variable(), None);

    let one: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(7));
    assert!(one.is_constant());
    assert_eq!(one.constant_value(), Some(FieldElement::from_u64(7)));
    assert_eq!(one.as_single_variable(), None);

    let x: LinearCombination = LinearCombination::from_variable(Variable(3));
    assert!(!x.is_constant());
    assert_eq!(x.constant_value(), None);
    assert_eq!(x.as_single_variable(), Some(Variable(3)));

    let cancelled: LinearCombination = LinearCombination::from_variable(Variable(3))
        - LinearCombination::from_variable(Variable(3));
    assert!(cancelled.is_constant());
    assert_eq!(cancelled.constant_value(), Some(FieldElement::zero()));
    assert_eq!(cancelled.as_single_variable(), None);
}

#[test]
fn test_evaluate_oob_returns_error() {
    let x = Variable(10); // index 10, way out of bounds
    let mut lc = LinearCombination::zero();
    lc.add_term(x, FieldElement::ONE);
    let witness = vec![FieldElement::ONE]; // only 1 element
    assert_eq!(
        lc.evaluate(&witness),
        Err(ConstraintError::VariableOutOfBounds {
            variable: 10,
            witness_len: 1,
        })
    );
}

#[test]
fn test_enforce_equal() {
    let mut cs = ConstraintSystem::new();
    let x = cs.alloc_witness(); // index 1
    let y = cs.alloc_witness(); // index 2

    // x = y
    cs.enforce_equal(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(y),
    );

    // Satisfying: x=7, y=7
    let good = vec![
        FieldElement::ONE,
        FieldElement::from_u64(7),
        FieldElement::from_u64(7),
    ];
    assert!(cs.verify(&good).is_ok());

    // Failing: x=7, y=8
    let bad = vec![
        FieldElement::ONE,
        FieldElement::from_u64(7),
        FieldElement::from_u64(8),
    ];
    assert!(cs.verify(&bad).is_err());
}

#[test]
fn count_mode_reports_constraints_without_retaining_rows() {
    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();
    let z = cs.alloc_witness();
    cs.disable_constraint_retention();

    cs.enforce(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(y),
        LinearCombination::from_variable(z),
    );
    cs.enforce_equal(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(z),
    );

    assert_eq!(cs.num_constraints(), 2);
    assert!(cs.constraints().is_empty());
    assert!(!cs.constraint_retention_enabled());
    assert_eq!(cs.num_variables(), 4);
}

#[test]
fn count_only_non_linear_mul_fast_path_counts_one_row() {
    let mut cs: ConstraintSystem = ConstraintSystem::new();
    cs.disable_constraint_retention();
    cs.enable_incremental_collapse_count_only();

    let out = cs
        .try_count_only_non_linear_mul()
        .expect("count-only non-linear fast path active");

    assert_eq!(out, Variable(1));
    assert_eq!(cs.num_variables(), 2);
    assert_eq!(cs.num_constraints(), 1);
    assert!(cs.constraints().is_empty());
}

#[test]
fn test_quadratic_expression() {
    // Circuit: prove knowledge of x such that x^2 + x + 5 = 35 (public)
    // x = 5 is the solution
    let mut cs = ConstraintSystem::new();

    let out = cs.alloc_input(); // public: 35
    let x = cs.alloc_witness(); // private: 5
    let x_sq = cs.alloc_witness(); // intermediate: x^2 = 25

    // Constraint 1: x * x = x_sq
    cs.enforce(
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(x),
        LinearCombination::from_variable(x_sq),
    );

    // Constraint 2: (x_sq + x + 5) * 1 = out
    // i.e. x_sq + x + 5*ONE = out
    let mut lhs = LinearCombination::zero();
    lhs.add_term(x_sq, FieldElement::ONE);
    lhs.add_term(x, FieldElement::ONE);
    lhs.add_term(Variable::ONE, FieldElement::from_u64(5));

    cs.enforce_equal(lhs, LinearCombination::from_variable(out));

    assert_eq!(cs.num_constraints(), 2);

    // Witness: ONE=1, out=35, x=5, x_sq=25
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(35),
        FieldElement::from_u64(5),
        FieldElement::from_u64(25),
    ];

    assert!(cs.verify(&witness).is_ok());
}

#[test]
fn test_mul_lc_helper() {
    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();

    let product_var = cs.mul_lc(
        &LinearCombination::from_variable(a),
        &LinearCombination::from_variable(b),
    );

    // product_var should be index 3 (ONE=0, a=1, b=2, product=3)
    assert_eq!(product_var.index(), 3);
    assert_eq!(cs.num_constraints(), 1);

    // Verify: a=6, b=7, product=42
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(6),
        FieldElement::from_u64(7),
        FieldElement::from_u64(42),
    ];
    assert!(cs.verify(&witness).is_ok());
}

#[test]
fn test_constant_lc_is_constant() {
    let lc: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(42));
    assert!(lc.is_constant());
    assert_eq!(lc.constant_value(), Some(FieldElement::from_u64(42)));
}

#[test]
fn test_zero_lc_is_constant() {
    let lc: LinearCombination = LinearCombination::zero();
    assert!(lc.is_constant());
    assert_eq!(lc.constant_value(), Some(FieldElement::ZERO));
}

#[test]
fn test_variable_lc_not_constant() {
    let lc: LinearCombination = LinearCombination::from_variable(Variable(1));
    assert!(!lc.is_constant());
    assert_eq!(lc.constant_value(), None);
}

#[test]
fn test_mixed_lc_not_constant() {
    let mut lc: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(5));
    lc.add_term(Variable(1), FieldElement::ONE);
    assert!(!lc.is_constant());
    assert_eq!(lc.constant_value(), None);
}

#[test]
fn test_constant_sum() {
    // Adding two constants should still be constant
    let a: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(3));
    let b: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(7));
    let sum = a + b;
    assert!(sum.is_constant());
    assert_eq!(sum.constant_value(), Some(FieldElement::from_u64(10)));
}

#[test]
fn test_lc_arithmetic() {
    let x = Variable(1);
    let y = Variable(2);

    let lc_x: LinearCombination = LinearCombination::from_variable(x);
    let lc_y: LinearCombination = LinearCombination::from_variable(y);

    // x + y
    let sum = lc_x.clone() + lc_y.clone();
    assert_eq!(sum.terms.len(), 2);

    // x - y
    let diff = lc_x.clone() - lc_y.clone();
    assert_eq!(diff.terms.len(), 2);

    // 3 * x
    let scaled = lc_x * FieldElement::from_u64(3);
    assert_eq!(scaled.terms.len(), 1);
    assert_eq!(scaled.terms[0].1, FieldElement::from_u64(3));
}

#[test]
fn test_lc_simplify_cancels_vars() {
    // x - x should simplify to constant zero
    let x = Variable(1);
    let lc: LinearCombination =
        LinearCombination::from_variable(x) - LinearCombination::from_variable(x);
    assert!(lc.is_constant());
    assert_eq!(lc.constant_value(), Some(FieldElement::ZERO));
}

#[test]
fn test_lc_simplify_merges_same_var() {
    // 3x + 5x -> 8x (not single variable since coeff != 1)
    let x = Variable(1);
    let a: LinearCombination = LinearCombination::from_variable(x) * FieldElement::from_u64(3);
    let b: LinearCombination = LinearCombination::from_variable(x) * FieldElement::from_u64(5);
    let sum = a + b;
    let simplified = sum.simplify();
    assert_eq!(simplified.terms.len(), 1);
    assert_eq!(simplified.terms[0].1, FieldElement::from_u64(8));
    assert!(sum.as_single_variable().is_none()); // coeff is 8, not 1
}

#[test]
fn test_lc_as_single_variable_after_cancellation() {
    // 2x - x -> x (single variable)
    let x = Variable(1);
    let two_x: LinearCombination = LinearCombination::from_variable(x) * FieldElement::from_u64(2);
    let one_x: LinearCombination = LinearCombination::from_variable(x);
    let diff = two_x - one_x;
    assert_eq!(diff.as_single_variable(), Some(x));
}

#[test]
fn test_lc_constant_with_cancellation() {
    // (5*ONE + 3x) - 3x -> constant 5
    let x = Variable(1);
    let mut a: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(5));
    a.add_term(x, FieldElement::from_u64(3));
    let b = LinearCombination::from_variable(x) * FieldElement::from_u64(3);
    let diff = a - b;
    assert!(diff.is_constant());
    assert_eq!(diff.constant_value(), Some(FieldElement::from_u64(5)));
}
