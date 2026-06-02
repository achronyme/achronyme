use super::*;

// ============================================================================
// L4: Division-by-zero tests — all paths in both backends
// ============================================================================

#[test]
fn test_r1cs_div_by_zero_witness_error() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a / b, out)";

    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::ZERO); // div by zero
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let result = wg.generate(&inputs);
    assert!(
        result.is_err(),
        "R1CS witness gen should error on div by zero"
    );
}

#[test]
fn test_plonkish_div_by_zero_witness_error() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a / b, out)";

    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let result = wg.generate(&inputs, &mut compiler.system.assignments);
    assert!(
        result.is_err(),
        "Plonkish witness gen should error on div by zero"
    );
}

#[test]
fn test_r1cs_div_by_zero_in_expression() {
    // Division where denominator is a computed zero: (a - a) = 0
    // With M3 (LC simplify), `a - a` is detected as constant zero at compile time,
    // so this now errors during compilation rather than witness generation.
    let pub_names = &["out"];
    let wit_names = &["a"];
    let source = "assert_eq(a / (a - a), out)";

    let program: ir::types::IrProgram =
        IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = R1CSCompiler::new();
    let result = compiler.compile_ir(&program);
    assert!(
        result.is_err(),
        "div by computed zero should error at compile time"
    );
}

#[test]
fn test_r1cs_div_valid_witness_passes() {
    // Ensure valid division works correctly
    let a = FieldElement::from_u64(42);
    let b = FieldElement::from_u64(7);
    let expected = a.div(&b).unwrap();

    r1cs_verify(
        &[("out", expected)],
        &[("a", a), ("b", b)],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_plonkish_div_valid_witness_passes() {
    let a = FieldElement::from_u64(42);
    let b = FieldElement::from_u64(7);
    let expected = a.div(&b).unwrap();

    plonkish_verify(
        &[("out", expected)],
        &[("a", a), ("b", b)],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_r1cs_div_zero_numerator_passes() {
    // 0 / x = 0 should work
    r1cs_verify(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::from_u64(7))],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_plonkish_div_zero_numerator_passes() {
    // 0 / x = 0 should work
    plonkish_verify(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::from_u64(7))],
        "assert_eq(a / b, out)",
    );
}
