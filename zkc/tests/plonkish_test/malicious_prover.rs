use super::*;

// ============================================================================
// C1–C4: Malicious prover tests — copy-constrained constants must be tamper-proof
// ============================================================================

use constraints::plonkish::PlonkishError;

/// C1: Corrupting col_d on the IsZero enforce row (d=1→0) must be caught.
#[test]
fn test_c1_forge_is_zero_rejected() {
    let source = "let eq = x == y\nassert_eq(eq, out)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    // Honest witness passes
    compiler
        .system
        .verify()
        .expect("honest witness should pass");

    // Corrupt: find a row where col_constant == ONE and col_d has that value,
    // then set col_d to ZERO (simulating IsZero enforce_row corruption).
    let col_d = compiler.col_d;
    let col_const = compiler.col_constant;
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        let d_val = compiler.system.assignments.get(col_d, row);
        if const_val == FieldElement::ONE && d_val == FieldElement::ONE {
            compiler
                .system
                .assignments
                .set(col_d, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find an IsZero enforce row to corrupt");
    let err = compiler
        .system
        .verify()
        .expect_err("corrupted d=1→0 must fail");
    assert!(
        matches!(err, PlonkishError::CopyConstraintViolation { .. })
            || matches!(err, PlonkishError::GateNotSatisfied { .. }),
        "expected CopyConstraintViolation or GateNotSatisfied, got: {err}"
    );
}

/// C2: Corrupting col_d on the division inverse row (d=1→0) must be caught.
#[test]
fn test_c2_forge_division_rejected() {
    let source = "let c = x / y\nassert_eq(c, out)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(6));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler
        .system
        .verify()
        .expect("honest witness should pass");

    // Corrupt col_d on the inverse row (d=1) to 0
    let col_d = compiler.col_d;
    let col_const = compiler.col_constant;
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        let d_val = compiler.system.assignments.get(col_d, row);
        if const_val == FieldElement::ONE && d_val == FieldElement::ONE {
            compiler
                .system
                .assignments
                .set(col_d, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find a division inverse row to corrupt");
    let err = compiler
        .system
        .verify()
        .expect_err("corrupted d=1→0 must fail");
    assert!(
        matches!(err, PlonkishError::CopyConstraintViolation { .. })
            || matches!(err, PlonkishError::GateNotSatisfied { .. }),
        "expected CopyConstraintViolation or GateNotSatisfied, got: {err}"
    );
}

/// C3: Corrupting a bit decomposition coefficient (col_b = 2^i → 0) must be caught.
#[test]
fn test_c3_forge_bit_coeff_rejected() {
    let source = "let r = a < b\nassert_eq(r, out)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["a", "b"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ONE);

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler
        .system
        .verify()
        .expect("honest witness should pass");

    // Corrupt: find a row where col_constant has a power-of-two (2^i for i>0)
    // in col_b, and zero it out.
    let col_b = compiler.col_b;
    let col_const = compiler.col_constant;
    let two = FieldElement::from_u64(2);
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        if const_val == two {
            compiler
                .system
                .assignments
                .set(col_b, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(
        corrupted,
        "should find a bit coefficient row (2^1) to corrupt"
    );
    let err = compiler
        .system
        .verify()
        .expect_err("corrupted 2^i→0 must fail");
    assert!(
        matches!(err, PlonkishError::CopyConstraintViolation { .. })
            || matches!(err, PlonkishError::GateNotSatisfied { .. }),
        "expected CopyConstraintViolation or GateNotSatisfied, got: {err}"
    );
}

/// C4: Corrupting the addition identity (col_b = 1 → 2) must be caught.
#[test]
fn test_c4_forge_addition_identity_rejected() {
    let source = "let r = x + y\nassert_eq(r, out)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(20));
    inputs.insert("y".to_string(), FieldElement::from_u64(22));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler
        .system
        .verify()
        .expect("honest witness should pass");

    // Corrupt: find a row where col_b=1 (addition identity) and set it to 2
    let col_b = compiler.col_b;
    let col_const = compiler.col_constant;
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        let b_val = compiler.system.assignments.get(col_b, row);
        if const_val == FieldElement::ONE && b_val == FieldElement::ONE {
            compiler
                .system
                .assignments
                .set(col_b, row, FieldElement::from_u64(2));
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find an addition identity row to corrupt");
    let err = compiler
        .system
        .verify()
        .expect_err("corrupted b=1→2 must fail");
    assert!(
        matches!(err, PlonkishError::CopyConstraintViolation { .. })
            || matches!(err, PlonkishError::GateNotSatisfied { .. }),
        "expected CopyConstraintViolation or GateNotSatisfied, got: {err}"
    );
}
