use super::*;

// ============================================================================
// Parity tests: IR soundness (from r1cs_ir_test.rs)
// ============================================================================

#[test]
fn test_plonkish_ir_const_fold() {
    // Constant folding: 2 + 3 should fold, no extra rows
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(15));
    inputs.insert("x".to_string(), FieldElement::from_u64(10));

    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit("assert_eq(x + 2 + 3, out)", &["out"], &["x"])
            .unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler.system.verify().expect("verification failed");
}

#[test]
fn test_plonkish_ir_assert_false_fails() {
    let source = "assert(flag)";
    let mut program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["flag"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ZERO);

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "assert(0) must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_ir_is_eq_soundness() {
    // x=5, y=10 but claim eq=1 → should be rejected
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("expected".to_string(), FieldElement::ONE); // WRONG

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "claiming 5 == 10 must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_ir_is_neq_soundness() {
    // x=7, y=7 but claim neq=1 → should be rejected
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(7));
    inputs.insert("y".to_string(), FieldElement::from_u64(7));
    inputs.insert("expected".to_string(), FieldElement::ONE); // WRONG

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "claiming 7 != 7 must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_ir_is_lt_soundness() {
    // a=10, b=3 but claim lt=1 → should be rejected
    let source = "let lt = a < b\nassert_eq(lt, expected)";
    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("expected".to_string(), FieldElement::ONE); // WRONG

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "claiming 10 < 3 must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_ir_and_non_boolean_fails() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(2)); // NOT boolean
    inputs.insert("b".to_string(), FieldElement::ONE);
    inputs.insert("expected".to_string(), FieldElement::from_u64(2));

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "a=2 should fail boolean enforcement in Plonkish And"
    );
}

#[test]
fn test_plonkish_ir_or_non_boolean_fails() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    let mut program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3)); // NOT boolean
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("expected".to_string(), FieldElement::from_u64(3));

    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    assert!(
        compiler.system.verify().is_err(),
        "a=3 should fail boolean enforcement in Plonkish Or"
    );
}

#[test]
fn test_plonkish_ir_division_malicious_witness() {
    // Compile a/b, claim out=99 when a=42, b=7 (correct is 6)
    let source = "assert_eq(a / b, out)";

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(99)); // WRONG

    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["a", "b"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    let result = compiler.compile_ir_with_witness(&program, &inputs);
    assert!(
        result.is_err(),
        "forged division result must fail in Plonkish"
    );
}

#[test]
fn test_plonkish_ir_array_access() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(20));

    let source = "let a = [x, y]\nassert_eq(a[0], x)\nassert_eq(a[1], y)";
    compile_source(source, &[], &["x", "y"], &inputs);
}

#[test]
fn test_plonkish_ir_array_in_function() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(30));
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));

    let source = "fn add(x, y) { x + y }\nassert_eq(add(a, b), out)";
    compile_source(source, &["out"], &["a", "b"], &inputs);
}
