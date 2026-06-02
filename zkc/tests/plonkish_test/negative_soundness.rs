use super::*;

// ============================================================================
// L2: Negative tests — invalid witnesses must be rejected
// ============================================================================

#[test]
fn test_plonkish_wrong_mul_rejected() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a * b, out)";

    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(99)); // wrong: 6*7=42

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "wrong product should be rejected"
    );
}

#[test]
fn test_plonkish_wrong_assert_eq_rejected() {
    let pub_names: &[&str] = &[];
    let wit_names = &["x", "y"];
    let source = "assert_eq(x, y)";

    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(20)); // x != y

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "unequal values in assert_eq should be rejected"
    );
}

#[test]
fn test_plonkish_wrong_mux_output_rejected() {
    let pub_names = &["out"];
    let wit_names = &["c", "a", "b"];
    let source = r#"
        let r = mux(c, a, b)
        assert_eq(r, out)
    "#;

    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("c".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    inputs.insert("out".to_string(), FieldElement::from_u64(99)); // wrong: mux(1,10,20)=10

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "wrong mux output should be rejected"
    );
}

#[test]
fn test_plonkish_wrong_comparison_rejected() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;

    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ZERO); // wrong: 3 < 7 is true (1)

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "wrong comparison result should be rejected"
    );
}

#[test]
fn test_plonkish_missing_input_error() {
    let program =
        ir::IrLowering::<Bn254Fr>::lower_circuit("assert_eq(x, y)", &[], &["x", "y"]).unwrap();

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    // missing "y"

    let result = wg.generate(&inputs, &mut compiler.system.assignments);
    assert!(result.is_err(), "missing input should error");
}

// ============================================================================
// Soundness tests — verify IsZero gadget with equal and unequal values
// ============================================================================

#[test]
fn test_plonkish_is_eq_equal_values() {
    // x == y where x=5, y=5 → result should be 1 (true)
    // This exercises the IsZeroRow witness op with diff=0
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let eq = x == y
        assert_eq(eq, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

#[test]
fn test_plonkish_is_eq_unequal_values() {
    // x == y where x=5, y=10 → result should be 0 (false)
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let eq = x == y
        assert_eq(eq, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

#[test]
fn test_plonkish_is_neq_equal_values() {
    // x != y where x=7, y=7 → result should be 0
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(7));
    inputs.insert("y".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let neq = x != y
        assert_eq(neq, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

#[test]
fn test_plonkish_is_eq_wrong_result_rejected() {
    // x == y where x=5, y=10 but we claim result=1 (forged equality)
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    let program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("expected".to_string(), FieldElement::ONE); // WRONG

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "claiming 5 == 10 must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_wrong_poseidon_rejected() {
    let source = "assert_eq(poseidon(l, r), out)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["l", "r"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("l".to_string(), FieldElement::from_u64(1));
    inputs.insert("r".to_string(), FieldElement::from_u64(2));
    inputs.insert("out".to_string(), FieldElement::from_u64(12345)); // WRONG

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "wrong Poseidon hash should be rejected by Plonkish backend"
    );
}

// ============================================================================
// H5: range_check with zero value must pass (selector-based lookup)
// ============================================================================

#[test]
fn test_plonkish_range_check_zero_value() {
    // range_check(x, 8) with x=0 should pass — 0 is in [0, 256)
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        range_check(x, 8)
        assert_eq(x, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}
