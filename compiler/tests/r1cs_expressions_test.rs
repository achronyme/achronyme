use compiler::r1cs_backend::R1CSCompiler;
use compiler::r1cs_error::R1CSError;
use ir::IrError;
use ir::IrLowering;

/// Helper: lower source through the IR pipeline, optimize, and compile to R1CS.
/// Returns the R1CSCompiler so tests can inspect constraint counts etc.
fn ir_compile(source: &str, public: &[&str], witness: &[&str]) -> Result<R1CSCompiler, String> {
    let mut prog = IrLowering::lower_circuit(source, public, witness)
        .map_err(|e| format!("IR: {e}"))?;
    ir::passes::optimize(&mut prog);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&prog).map_err(|e| format!("R1CS: {e}"))?;
    Ok(rc)
}

#[test]
fn test_r1cs_compile_number() {
    let rc = ir_compile("42", &[], &[]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_compile_negative_number() {
    let rc = ir_compile("-7", &[], &[]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_compile_identifier() {
    let rc = ir_compile("x", &[], &["x"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_reject_string() {
    let err = IrLowering::lower_circuit("\"hello\"", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_bool_literals() {
    // true and false are now allowed in circuits as 1 and 0
    ir_compile("true", &[], &[]).unwrap();
    ir_compile("false", &[], &[]).unwrap();
}

#[test]
fn test_r1cs_reject_nil() {
    let err = IrLowering::lower_circuit("nil", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_reject_decimal() {
    let err = IrLowering::lower_circuit("3.14", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::TypeNotConstrainable(..)));
}

#[test]
fn test_r1cs_addition_free() {
    let rc = ir_compile("a + b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "addition should generate 0 constraints");
}

#[test]
fn test_r1cs_subtraction_free() {
    let rc = ir_compile("a - b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_mul_by_constant_free() {
    let rc = ir_compile("a * 3", &[], &["a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "multiplication by constant should be free");
}

#[test]
fn test_r1cs_mul_variables_one_constraint() {
    let rc = ir_compile("a * b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 1, "variable * variable should be 1 constraint");
}

#[test]
fn test_r1cs_div_constant_free() {
    let rc = ir_compile("a / 7", &[], &["a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "division by constant should be free");
}

#[test]
fn test_r1cs_div_variables_two_constraints() {
    let rc = ir_compile("a / b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 2, "a / b should generate 2 constraints");
}

#[test]
fn test_r1cs_pow_literal() {
    let rc = ir_compile("x ^ 3", &[], &["x"]).unwrap();
    // x^3 = x * x * x: first x*x (1 constraint), then result * x (1 constraint) = 2
    assert_eq!(rc.cs.num_constraints(), 2, "x^3 should generate 2 constraints");
}

#[test]
fn test_r1cs_pow_variable_rejected() {
    let err = IrLowering::lower_circuit("x ^ n", &[], &["x", "n"]).unwrap_err();
    assert!(matches!(err, IrError::UnsupportedOperation(..)));
}

#[test]
fn test_r1cs_pow_zero() {
    let rc = ir_compile("x ^ 0", &[], &["x"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_pow_one() {
    let rc = ir_compile("x ^ 1", &[], &["x"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_let_binding() {
    // let sum = a + b (0 constraints, just stores LC)
    // sum * 2 (0 constraints, scalar mul)
    let rc = ir_compile("let sum = a + b; sum * 2", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_negation_free() {
    let rc = ir_compile("-x", &[], &["x"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_r1cs_complex_expression_constraint_count() {
    // a * b + c * d should be 2 constraints (one for each mul)
    let rc = ir_compile("a * b + c * d", &[], &["a", "b", "c", "d"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_r1cs_assert_eq_one_constraint() {
    let rc = ir_compile("assert_eq(a, b)", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_reject_mut() {
    let err = IrLowering::lower_circuit("mut x = 5", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::UnsupportedOperation(..)));
}

#[test]
fn test_r1cs_reject_print() {
    let err = IrLowering::lower_circuit("print(42)", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::UnsupportedOperation(..)));
}

// ============================================================================
// New operators: &&, ||, ! (IR path)
// ============================================================================

#[test]
fn test_r1cs_and_expr() {
    // a && b = 2 boolean enforcements + 1 mul = 3 constraints
    let rc = ir_compile("a && b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_r1cs_or_expr() {
    // a || b = 2 boolean enforcements + 1 mul = 3 constraints
    let rc = ir_compile("a || b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_r1cs_not_expr() {
    // !x = boolean enforcement (1) = 1 constraint
    let rc = ir_compile("!x", &[], &["x"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 1);
}

#[test]
fn test_r1cs_not_constant_free() {
    // !true is purely constant via const_fold — 0 constraints
    let rc = ir_compile("!true", &[], &[]).unwrap();
    // Just verify it compiles without error
    let _ = rc;
}

#[test]
fn test_r1cs_comparison_via_ir() {
    // The IR path supports comparisons via the IsEq gadget (2 constraints).
    // (The old direct AST path rejected these, but IR handles them.)
    let rc = ir_compile("a == b", &[], &["a", "b"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 2, "IsEq gadget should produce 2 constraints");
}

#[test]
fn test_r1cs_error_has_display() {
    // Verify that R1CSError Display works with the new span field
    let err = R1CSError::UnsupportedOperation("test op".into(), None);
    let msg = format!("{err}");
    assert!(msg.contains("test op"));
    assert!(!msg.contains("["), "None span should not produce brackets");
}
