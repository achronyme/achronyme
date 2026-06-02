use super::*;

// ============================================================================
// Parity tests: expressions (from r1cs_expressions_test.rs)
// ============================================================================

#[test]
fn test_plonkish_compile_number() {
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit("42", &[], &[]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_plonkish_bool_literals() {
    let prog_t = ir::IrLowering::<Bn254Fr>::lower_circuit("true", &[], &[]).unwrap();
    let mut comp_t = PlonkishCompiler::new();
    comp_t.compile_ir(&prog_t).unwrap();

    let prog_f = ir::IrLowering::<Bn254Fr>::lower_circuit("false", &[], &[]).unwrap();
    let mut comp_f = PlonkishCompiler::new();
    comp_f.compile_ir(&prog_f).unwrap();
}

#[test]
fn test_plonkish_addition_deferred() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(5));
    compile_source("assert_eq(a + b, 8)", &[], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_subtraction_deferred() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    compile_source("assert_eq(a - b, 7)", &[], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_mul_by_constant_free() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(7));
    compile_source("assert_eq(a * 3, 21)", &[], &["a"], &inputs);
}

#[test]
fn test_plonkish_div_constant_free() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(49));
    compile_source("assert_eq(a / 7, 7)", &[], &["a"], &inputs);
}

#[test]
fn test_plonkish_let_binding() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(5));
    compile_source(
        "let sum = a + b\nassert_eq(sum * 2, 16)",
        &[],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_negation_deferred() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::from_u64(5));
    // -x + x = 0, verify via assert_eq
    compile_source("assert_eq(-x + out, 0)", &[], &["x", "out"], &inputs);
}

#[test]
fn test_plonkish_complex_expr_row_count() {
    // a*b + c*d: 2 multiplications need rows
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(23));
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(5));
    inputs.insert("c".to_string(), FieldElement::from_u64(2));
    inputs.insert("d".to_string(), FieldElement::from_u64(4));

    let compiler = compile_source(
        "assert_eq(a * b + c * d, out)",
        &["out"],
        &["a", "b", "c", "d"],
        &inputs,
    );
    assert!(
        compiler.num_circuit_rows() >= 2,
        "a*b + c*d should need at least 2 rows, got {}",
        compiler.num_circuit_rows()
    );
}

#[test]
fn test_plonkish_and_expr() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::ONE);
    inputs.insert("b".to_string(), FieldElement::ONE);

    compile_source("assert_eq(a && b, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_or_expr() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), FieldElement::ONE);

    compile_source("assert_eq(a || b, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_not_expr() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::ONE);
    inputs.insert("x".to_string(), FieldElement::ZERO);

    compile_source("assert_eq(!x, out)", &["out"], &["x"], &inputs);
}
