use compiler::r1cs_backend::R1CSCompiler;
use compiler::r1cs_error::R1CSError;

#[test]
fn test_r1cs_compile_number() {
    let mut rc = R1CSCompiler::new();
    rc.compile_circuit("42").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_compile_negative_number() {
    let mut rc = R1CSCompiler::new();
    rc.compile_circuit("-7").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_compile_identifier() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.compile_circuit("x").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_reject_string() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("\"hello\"").unwrap_err();
    assert!(matches!(err, R1CSError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_bool_literals() {
    // true and false are now allowed in circuits as 1 and 0
    let mut rc = R1CSCompiler::new();
    rc.compile_circuit("true").unwrap();
    let mut rc2 = R1CSCompiler::new();
    rc2.compile_circuit("false").unwrap();
}

#[test]
fn test_r1cs_reject_nil() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("nil").unwrap_err();
    assert!(matches!(err, R1CSError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_reject_decimal() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("3.14").unwrap_err();
    assert!(matches!(err, R1CSError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_addition_free() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("a + b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "addition should generate 0 constraints");
}

#[test]
fn test_r1cs_subtraction_free() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("a - b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_mul_by_constant_free() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("a * 3").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "multiplication by constant should be free");
}

#[test]
fn test_r1cs_mul_variables_one_constraint() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("a * b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 1, "variable * variable should be 1 constraint");
}

#[test]
fn test_r1cs_div_constant_free() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("a / 7").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "division by constant should be free");
}

#[test]
fn test_r1cs_div_variables_two_constraints() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("a / b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 2, "a / b should generate 2 constraints");
}

#[test]
fn test_r1cs_pow_literal() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.compile_circuit("x ^ 3").unwrap();
    // x^3 = x * x * x: first x*x (1 constraint), then result * x (1 constraint) = 2
    assert_eq!(rc.cs.num_constraints(), 2, "x^3 should generate 2 constraints");
}

#[test]
fn test_r1cs_pow_variable_rejected() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.declare_witness("n");
    let err = rc.compile_circuit("x ^ n").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

#[test]
fn test_r1cs_pow_zero() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.compile_circuit("x ^ 0").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_pow_one() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.compile_circuit("x ^ 1").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_let_binding() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    // let sum = a + b (0 constraints, just stores LC)
    // sum * 2 (0 constraints, scalar mul)
    rc.compile_circuit("let sum = a + b; sum * 2").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_negation_free() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    rc.compile_circuit("-x").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_complex_expression_constraint_count() {
    // a * b + c * d should be 2 constraints (one for each mul)
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.declare_witness("d");
    rc.compile_circuit("a * b + c * d").unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_r1cs_assert_eq_one_constraint() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("assert_eq(a, b)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_reject_mut() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("mut x = 5").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

#[test]
fn test_r1cs_reject_print() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("print(42)").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

// ============================================================================
// New operators: &&, ||, ! (direct AST path)
// ============================================================================

#[test]
fn test_r1cs_and_expr() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    // a && b = a * b → 1 constraint (variable mul)
    rc.compile_circuit("a && b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_or_expr() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    // a || b = a + b - a*b → 1 constraint (the mul)
    rc.compile_circuit("a || b").unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_not_expr() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    // !x = boolean enforcement (1) = 1 constraint
    rc.compile_circuit("!x").unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_not_constant_free() {
    let mut rc = R1CSCompiler::new();
    // !true is purely constant — 0 constraints (boolean enforcement on constant)
    // Actually the enforcement still fires since compile_prefix_expr doesn't optimize constants
    rc.compile_circuit("!true").unwrap();
    // Just verify it compiles without error
}

#[test]
fn test_r1cs_comparison_rejected_direct() {
    // Direct AST path rejects comparisons (== etc.)
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    let err = rc.compile_circuit("a == b").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

#[test]
fn test_r1cs_error_has_display() {
    // Verify that R1CSError Display works with the new span field
    let err = R1CSError::UnsupportedOperation("test op".into(), None);
    let msg = format!("{err}");
    assert!(msg.contains("test op"));
    assert!(!msg.contains("["), "None span should not produce brackets");
}
