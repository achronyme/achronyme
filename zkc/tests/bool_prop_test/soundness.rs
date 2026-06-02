use super::*;

// ============================================================================
// Soundness: let b: Bool = witness must produce enforceable circuit
// ============================================================================

#[test]
fn soundness_let_bool_on_untyped_witness_enforced() {
    // The critical soundness test: `let b: Bool = x` where x is an untyped witness.
    // If x=5 is assigned, the circuit MUST reject the witness.
    let source = "witness x\nlet b: Bool = x\nassert(b)";
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Valid witness: x=1 → should pass
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut valid_inputs = HashMap::new();
    valid_inputs.insert("x".to_string(), FieldElement::from_u64(1));
    let witness = wg.generate(&valid_inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Malicious witness: x=5 → circuit MUST reject
    let mut bad_inputs = HashMap::new();
    bad_inputs.insert("x".to_string(), FieldElement::from_u64(5));
    let bad_witness = wg.generate(&bad_inputs).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject x=5 when annotated as Bool"
    );
}

#[test]
fn soundness_fn_return_bool_enforced() {
    // fn f(x: Field) -> Bool { x } — if body returns an untyped value,
    // the circuit must enforce boolean on the return value.
    let source = r#"
witness w
fn f(x: Field) -> Bool { x }
let r = f(w)
assert(r)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Valid: w=1 → passes (assert(r) requires r=1)
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut valid_inputs = HashMap::new();
    valid_inputs.insert("w".to_string(), FieldElement::ONE);
    let witness = wg.generate(&valid_inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Malicious: w=42 → must reject
    let mut bad_inputs = HashMap::new();
    bad_inputs.insert("w".to_string(), FieldElement::from_u64(42));
    let bad_witness = wg.generate(&bad_inputs).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject w=42 when fn return type is Bool"
    );
}

#[test]
fn soundness_fn_param_bool_enforced() {
    // fn f(b: Bool) { assert(b) } called with untyped witness
    let source = r#"
witness w
fn f(b: Bool) { assert(b) }
f(w)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Valid: w=1 → passes
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut valid_inputs = HashMap::new();
    valid_inputs.insert("w".to_string(), FieldElement::ONE);
    let witness = wg.generate(&valid_inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Malicious: w=3 → must reject
    let mut bad_inputs = HashMap::new();
    bad_inputs.insert("w".to_string(), FieldElement::from_u64(3));
    let bad_witness = wg.generate(&bad_inputs).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject w=3 when param type is Bool"
    );
}

// ============================================================================
// T-01: witness x: Bool declarations must emit enforcement constraint
// ============================================================================

#[test]
fn soundness_witness_bool_decl_enforced() {
    // `witness flag: Bool` must emit RangeCheck(flag, 1).
    // Without enforcement, a malicious prover can set flag=5.
    let source = r#"
witness flag: Bool
witness a: Field
witness b: Field
let r = mux(flag, a, b)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Valid: flag=1, a=10, b=20 → r=10
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut valid = HashMap::new();
    valid.insert("flag".to_string(), FieldElement::ONE);
    valid.insert("a".to_string(), FieldElement::from_u64(10));
    valid.insert("b".to_string(), FieldElement::from_u64(20));
    let witness = wg.generate(&valid).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Malicious: flag=5 → circuit MUST reject
    let mut bad = HashMap::new();
    bad.insert("flag".to_string(), FieldElement::from_u64(5));
    bad.insert("a".to_string(), FieldElement::from_u64(10));
    bad.insert("b".to_string(), FieldElement::from_u64(20));
    let bad_witness = wg.generate(&bad).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject flag=5 for `witness flag: Bool`"
    );
}

#[test]
fn soundness_witness_bool_array_decl_enforced() {
    // `witness indices[2]: Bool` must emit RangeCheck per element.
    let source = r#"
witness indices[2]: Bool
witness a: Field
witness b: Field
let r1 = mux(indices[0], a, b)
let r2 = mux(indices[1], b, a)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Valid: indices=[0, 1]
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut valid = HashMap::new();
    valid.insert("indices_0".to_string(), FieldElement::ZERO);
    valid.insert("indices_1".to_string(), FieldElement::ONE);
    valid.insert("a".to_string(), FieldElement::from_u64(10));
    valid.insert("b".to_string(), FieldElement::from_u64(20));
    let witness = wg.generate(&valid).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Malicious: indices_0=3 → circuit MUST reject
    let mut bad = HashMap::new();
    bad.insert("indices_0".to_string(), FieldElement::from_u64(3));
    bad.insert("indices_1".to_string(), FieldElement::ONE);
    bad.insert("a".to_string(), FieldElement::from_u64(10));
    bad.insert("b".to_string(), FieldElement::from_u64(20));
    let bad_witness = wg.generate(&bad).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject indices_0=3 for `witness indices[2]: Bool`"
    );
}

#[test]
fn soundness_public_bool_decl_enforced() {
    // `public flag: Bool` must also emit enforcement.
    let source = r#"
public flag: Bool
witness a: Field
witness b: Field
let r = mux(flag, a, b)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("should lower");
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).unwrap();

    // Malicious: flag=7 → circuit MUST reject
    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut bad = HashMap::new();
    bad.insert("flag".to_string(), FieldElement::from_u64(7));
    bad.insert("a".to_string(), FieldElement::from_u64(10));
    bad.insert("b".to_string(), FieldElement::from_u64(20));
    let bad_witness = wg.generate(&bad).unwrap();
    assert!(
        compiler.cs.verify(&bad_witness).is_err(),
        "circuit must reject flag=7 for `public flag: Bool`"
    );
}
