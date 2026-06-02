use super::*;

// ============================================================================
// Parity tests: control flow (from r1cs_control_flow_test.rs)
// ============================================================================

#[test]
fn test_plonkish_if_else_boolean_enforcement() {
    // flag=2 should fail (non-boolean condition)
    let source = "let result = if flag { a } else { b }; assert_eq(result, out)";
    let program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["flag", "a", "b"]).unwrap();

    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let flag_val = FieldElement::from_u64(2);
    let diff = a_val.sub(&b_val);
    let mux_prod = flag_val.mul(&diff);
    let result = mux_prod.add(&b_val);

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), result);
    inputs.insert("flag".to_string(), flag_val);
    inputs.insert("a".to_string(), a_val);
    inputs.insert("b".to_string(), b_val);

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "flag=2 should fail boolean enforcement in Plonkish"
    );
}

#[test]
fn test_plonkish_fn_declaration_accepted() {
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit("fn foo() { 1 }", &[], &[]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(
        compiler.num_circuit_rows(),
        0,
        "fn declaration without call should produce 0 rows"
    );
}
