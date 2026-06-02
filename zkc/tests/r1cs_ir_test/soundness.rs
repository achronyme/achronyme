use super::*;

// ====================================================================
// Soundness tests — verify cheating prover cannot forge results
// ====================================================================

#[test]
fn ir_assert_false_fails_verification() {
    let source = "assert(flag)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["flag"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "assert(0) must fail R1CS verification"
    );
}

#[test]
fn ir_is_eq_soundness_wrong_result_rejected() {
    // x == y where x=5, y=10 but we claim result=1 (forged equality)
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(5));
    inputs.insert("y".into(), FieldElement::from_u64(10));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 5 != 10

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 5 == 10 must fail verification (IsZero gadget soundness)"
    );
}

#[test]
fn ir_is_neq_soundness_wrong_result_rejected() {
    // x != y where x=7, y=7 but we claim result=1 (forged inequality)
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(7));
    inputs.insert("y".into(), FieldElement::from_u64(7));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 7 == 7

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 7 != 7 must fail verification"
    );
}

#[test]
fn ir_is_lt_soundness_wrong_result_rejected() {
    let source = "let lt = a < b\nassert_eq(lt, expected)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(10));
    inputs.insert("b".into(), FieldElement::from_u64(3));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 10 >= 3

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 10 < 3 must fail verification"
    );
}

#[test]
fn ir_and_non_boolean_input_fails() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(2)); // NOT boolean
    inputs.insert("b".into(), FieldElement::ONE);
    inputs.insert("expected".into(), FieldElement::from_u64(2));

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "a=2 should fail boolean enforcement in And operator"
    );
}

#[test]
fn ir_or_non_boolean_input_fails() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(3)); // NOT boolean
    inputs.insert("b".into(), FieldElement::ZERO);
    inputs.insert("expected".into(), FieldElement::from_u64(3));

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "a=3 should fail boolean enforcement in Or operator"
    );
}
