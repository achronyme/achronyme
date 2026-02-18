use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// R1CS range_check tests
// ============================================================================

#[test]
fn test_r1cs_range_check_valid_8bit() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(200)); // 200 < 256

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
}

#[test]
fn test_r1cs_range_check_invalid_8bit() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(256)); // 256 >= 2^8

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    // Should fail verification — 256 doesn't fit in 8 bits
    assert!(compiler.cs.verify(&witness).is_err());
}

#[test]
fn test_r1cs_range_check_cost_equals_bits_plus_1() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    // 8 boolean constraints + 1 sum equality = 9 constraints
    assert_eq!(compiler.cs.num_constraints(), 9);
}

#[test]
fn test_r1cs_range_check_16bit() {
    let source = r#"
        range_check(x, 16)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    // 16 boolean + 1 sum = 17 constraints
    assert_eq!(compiler.cs.num_constraints(), 17);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(65535)); // max 16-bit

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
}

#[test]
fn test_r1cs_range_check_zero() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::ZERO);

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
}

// ============================================================================
// Plonkish range_check tests
// ============================================================================

#[test]
fn test_plonkish_range_check_valid_lookup() {
    let source = r#"
        range_check(x, 4)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::new();
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
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::new();
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
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    // Witness input uses 1 row, materialization of x cell + range check row
    // The key point: it should be much fewer rows than R1CS constraints
    let rows = compiler.num_circuit_rows();
    // Witness allocation (1 row) + materialization (1 row for cell copy) + range check (1 row)
    assert!(rows <= 3, "expected <= 3 rows, got {rows}");
}

// ============================================================================
// Comparison tests: Plonkish O(1) vs R1CS O(bits)
// ============================================================================

#[test]
fn test_plonkish_vs_r1cs_8bit() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program_r1cs = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();
    let program_plonk = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut r1cs = R1CSCompiler::new();
    r1cs.compile_ir(&program_r1cs).unwrap();

    let mut plonk = PlonkishCompiler::new();
    plonk.compile_ir(&program_plonk).unwrap();

    let r1cs_cost = r1cs.cs.num_constraints(); // 9 (8 + 1)
    let plonk_rows = plonk.num_circuit_rows();

    assert_eq!(r1cs_cost, 9, "R1CS 8-bit range check should cost 9 constraints");
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
    let program_r1cs = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();
    let program_plonk = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();

    let mut r1cs = R1CSCompiler::new();
    r1cs.compile_ir(&program_r1cs).unwrap();

    let mut plonk = PlonkishCompiler::new();
    plonk.compile_ir(&program_plonk).unwrap();

    let r1cs_cost = r1cs.cs.num_constraints(); // 17 (16 + 1)
    let plonk_rows = plonk.num_circuit_rows();

    assert_eq!(r1cs_cost, 17, "R1CS 16-bit range check should cost 17 constraints");
    assert!(
        plonk_rows < r1cs_cost,
        "Plonkish should use fewer rows ({plonk_rows}) than R1CS constraints ({r1cs_cost})"
    );
}

// ============================================================================
// IR-level range_check tests
// ============================================================================

#[test]
fn test_range_check_const_fold() {
    // range_check on a constant that fits should fold
    let source = r#"
        range_check(42, 8)
    "#;
    let mut program = IrLowering::lower_circuit(source, &[], &[]).unwrap();
    ir::passes::optimize(&mut program);

    // After optimization, the RangeCheck should still be present
    // (it has side effects), but the constant should propagate
    let has_range_check = program.instructions.iter().any(|inst| {
        matches!(inst, ir::Instruction::RangeCheck { .. })
    });
    assert!(has_range_check, "RangeCheck should be preserved (has side effects)");
}

#[test]
fn test_range_check_taint_constrains() {
    let source = r#"
        range_check(x, 8)
    "#;
    let program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();
    let warnings = ir::passes::analyze(&program);

    // x should NOT be under-constrained because range_check constrains it
    let under_constrained = warnings.iter().any(|w| {
        format!("{w}").contains("under-constrained")
    });
    assert!(
        !under_constrained,
        "x should be constrained by range_check, but got warnings: {:?}",
        warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>()
    );
}

// ============================================================================
// Backend comparison: simple mul produces same result
// ============================================================================

#[test]
fn test_both_backends_simple_mul() {
    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    // R1CS
    let program_r1cs = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();
    let mut r1cs = R1CSCompiler::new();
    r1cs.compile_ir(&program_r1cs).unwrap();
    let wg_r1cs = WitnessGenerator::from_compiler(&r1cs);
    let witness = wg_r1cs.generate(&inputs).unwrap();
    r1cs.cs.verify(&witness).unwrap();

    // Plonkish
    let program_plonk = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();
    let mut plonk = PlonkishCompiler::new();
    plonk.compile_ir(&program_plonk).unwrap();
    let wg_plonk = PlonkishWitnessGenerator::from_compiler(&plonk);
    wg_plonk
        .generate(&inputs, &mut plonk.system.assignments)
        .unwrap();
    plonk.system.verify().unwrap();
}
