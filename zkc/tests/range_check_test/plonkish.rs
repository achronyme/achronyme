use super::*;

// ============================================================================
// Plonkish range_check tests
// ============================================================================

#[test]
fn test_plonkish_range_check_valid_lookup() {
    let source = r#"
        range_check(x, 4)
    "#;
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(15)); // max 4-bit

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();
}

#[test]
fn test_plonkish_range_check_invalid_lookup() {
    let source = r#"
        range_check(x, 4)
    "#;
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(16)); // 16 >= 2^4

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    // Should fail lookup
    assert!(compiler.system.verify().is_err());
}

#[test]
fn test_plonkish_range_check_cost_one_row() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    // Witness input uses 1 row, materialization of x cell + range check row
    // The key point: it should be much fewer rows than R1CS constraints
    let rows = compiler.num_circuit_rows();
    // Witness allocation (1 row) + materialization (1 row for cell copy) + range check (1 row)
    assert!(rows <= 3, "expected <= 3 rows, got {rows}");
}

// ============================================================================
// T8: Plonkish range_check edge cases
// ============================================================================

#[test]
fn test_plonkish_range_check_1bit_zero() {
    // bits=1: value=0 should pass
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 1)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ZERO);
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();
}

#[test]
fn test_plonkish_range_check_1bit_one() {
    // bits=1: value=1 should pass
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 1)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ONE);
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();
}

#[test]
fn test_plonkish_range_check_1bit_invalid() {
    // bits=1: value=2 should fail
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 1)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(2));
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "value=2 should not fit in 1 bit (Plonkish)"
    );
}

#[test]
fn test_plonkish_range_check_boundary_exact_max() {
    // bits=8: value=255 (2^8 - 1) should pass
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 8)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(255));
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();
}

#[test]
fn test_plonkish_range_check_0bit_zero() {
    // bits=0: only value=0 should pass
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 0)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ZERO);
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();
}

#[test]
fn test_plonkish_range_check_0bit_invalid() {
    // bits=0: value=1 should fail
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 0)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ONE);
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "value=1 should not fit in 0 bits"
    );
}

#[test]
fn test_plonkish_range_check_253bit_rejected() {
    // Plonkish uses lookup tables: bits=253 exceeds the max table size (2^16).
    // The compiler must reject this with an error, not panic.
    let program = IrLowering::<Bn254Fr>::lower_circuit("range_check(x, 253)", &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    let result = compiler.compile_ir(&program);
    assert!(
        result.is_err(),
        "Plonkish should reject 253-bit range check (table too large)"
    );
}

// ============================================================================
// Comparison tests: Plonkish O(1) vs R1CS O(bits)
// ============================================================================

#[test]
fn test_plonkish_vs_r1cs_8bit() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program_r1cs = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();
    let program_plonk = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    r1cs.compile_ir(&program_r1cs).unwrap();

    let mut plonk = PlonkishCompiler::<Bn254Fr>::new();
    plonk.compile_ir(&program_plonk).unwrap();

    let r1cs_cost = r1cs.cs.num_constraints(); // 9 (8 + 1)
    let plonk_rows = plonk.num_circuit_rows();

    assert_eq!(
        r1cs_cost, 9,
        "R1CS 8-bit range check should cost 9 constraints"
    );
    assert!(
        plonk_rows < r1cs_cost,
        "Plonkish should use fewer rows ({plonk_rows}) than R1CS constraints ({r1cs_cost})"
    );
}

#[test]
fn test_plonkish_vs_r1cs_16bit() {
    let source = r#"
        range_check(x, 16)
    "#;
    let program_r1cs = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();
    let program_plonk = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    r1cs.compile_ir(&program_r1cs).unwrap();

    let mut plonk = PlonkishCompiler::<Bn254Fr>::new();
    plonk.compile_ir(&program_plonk).unwrap();

    let r1cs_cost = r1cs.cs.num_constraints(); // 17 (16 + 1)
    let plonk_rows = plonk.num_circuit_rows();

    assert_eq!(
        r1cs_cost, 17,
        "R1CS 16-bit range check should cost 17 constraints"
    );
    assert!(
        plonk_rows < r1cs_cost,
        "Plonkish should use fewer rows ({plonk_rows}) than R1CS constraints ({r1cs_cost})"
    );
}
