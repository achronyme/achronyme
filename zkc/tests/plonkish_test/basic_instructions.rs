use super::*;

// ============================================================================
// Basic instruction tests
// ============================================================================

#[test]
fn test_const_no_rows() {
    let mut program = IrProgram::<Bn254Fr>::new();
    let v = program.fresh_var();
    program.push(Instruction::Const {
        result: v,
        value: FieldElement::from_u64(42),
    });

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_input_public() {
    let mut program = IrProgram::<Bn254Fr>::new();
    let v = program.fresh_var();
    program.push(Instruction::Input {
        result: v,
        name: "x".into(),
        visibility: Visibility::Public,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(7));

    let compiler = compile_and_verify(&program, &inputs);
    assert!(compiler.public_inputs.contains(&"x".to_string()));
}

#[test]
fn test_input_witness() {
    let mut program = IrProgram::<Bn254Fr>::new();
    let v = program.fresh_var();
    program.push(Instruction::Input {
        result: v,
        name: "w".into(),
        visibility: Visibility::Witness,
    });

    let mut inputs = HashMap::new();
    inputs.insert("w".to_string(), FieldElement::from_u64(99));

    let compiler = compile_and_verify(&program, &inputs);
    assert!(compiler.witnesses.contains(&"w".to_string()));
}

#[test]
fn test_add_deferred() {
    // x + y should produce a deferred add (materialized on demand)
    let mut program = IrProgram::<Bn254Fr>::new();
    let x = program.fresh_var();
    program.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let y = program.fresh_var();
    program.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    let sum = program.fresh_var();
    program.push(Instruction::Add {
        result: sum,
        lhs: x,
        rhs: y,
    });
    // Force materialization via assert_eq
    let const42 = program.fresh_var();
    program.push(Instruction::Const {
        result: const42,
        value: FieldElement::from_u64(42),
    });
    let eq = program.fresh_var();
    program.push(Instruction::AssertEq {
        result: eq,
        lhs: sum,
        rhs: const42,
        message: None,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(20));
    inputs.insert("y".to_string(), FieldElement::from_u64(22));
    compile_and_verify(&program, &inputs);
}

#[test]
fn test_mul_one_row() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    let compiler = compile_source(source, &["out"], &["a", "b"], &inputs);
    // Mul produces 1 arith row (at minimum)
    assert!(compiler.num_circuit_rows() >= 1);
}

#[test]
fn test_mul_const_no_row() {
    // Multiplying two constants should be folded, producing 0 arith rows
    let mut program = IrProgram::<Bn254Fr>::new();
    let a = program.fresh_var();
    program.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(6),
    });
    let b = program.fresh_var();
    program.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(7),
    });
    let c = program.fresh_var();
    program.push(Instruction::Mul {
        result: c,
        lhs: a,
        rhs: b,
    });

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_div_two_rows() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(6));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = x / y
        assert_eq(c, out)
    "#;
    let compiler = compile_source(source, &["out"], &["x", "y"], &inputs);
    // Division produces at least 2 arith rows
    assert!(compiler.num_circuit_rows() >= 2);
}

#[test]
fn test_mux_rows() {
    let mut inputs = HashMap::new();
    inputs.insert("cond".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let r = mux(cond, a, b)
        assert_eq(r, out)
    "#;
    let compiler = compile_source(source, &["out"], &["cond", "a", "b"], &inputs);
    assert!(compiler.num_circuit_rows() >= 2);
}

#[test]
fn test_assert_eq_copy() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(42));

    let source = r#"
        assert_eq(x, y)
    "#;
    let compiler = compile_source(source, &[], &["x", "y"], &inputs);
    // assert_eq should produce at least 1 copy constraint
    assert!(!compiler.system.copies.is_empty());
}
