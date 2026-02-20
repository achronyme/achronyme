use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use ir::types::{Instruction, IrProgram, Visibility};
use memory::FieldElement;

/// Helper: compile IR, generate witness, verify.
fn compile_and_verify(
    program: &IrProgram,
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler
        .system
        .verify()
        .expect("verification failed");
    compiler
}

/// Helper: build program from source string via IR lowering.
fn compile_source(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let program = ir::IrLowering::lower_circuit(source, public, witness).unwrap();
    compile_and_verify(&program, inputs)
}

// ============================================================================
// Basic instruction tests
// ============================================================================

#[test]
fn test_const_no_rows() {
    let mut program = IrProgram::new();
    let v = program.fresh_var();
    program.push(Instruction::Const {
        result: v,
        value: FieldElement::from_u64(42),
    });

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_input_public() {
    let mut program = IrProgram::new();
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
    let mut program = IrProgram::new();
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
    let mut program = IrProgram::new();
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
    let mut program = IrProgram::new();
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

    let mut compiler = PlonkishCompiler::new();
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

// ============================================================================
// IR-level circuit tests
// ============================================================================

#[test]
fn test_ir_simple_mul() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_ir_quadratic() {
    // x^2 + x + 5 = 35 → x = 5
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(35));
    inputs.insert("x".to_string(), FieldElement::from_u64(5));

    let source = r#"
        let y = x^2 + x + 5
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_for_unroll() {
    // Accumulate: sum = 1 + 2 + 3 + 4 = 10
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let acc = 0
        for i in 1..5 {
            let acc = acc + i
        }
        assert_eq(acc, out)
    "#;
    compile_source(source, &["out"], &[], &inputs);
}

#[test]
fn test_ir_negation() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let y = -(-x)
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_subtraction() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let r = x - y
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

// ============================================================================
// IsLt / IsLe tests
// ============================================================================

#[test]
fn test_is_lt_true() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_false() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(7));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_large_values() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(1_000_000));
    inputs.insert("b".to_string(), FieldElement::from_u64(9_999_999));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_le_strict_less() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(5));
    inputs.insert("b".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a <= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_le_false() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let r = a <= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_gt_via_plonkish() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a > b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_ge_strict_greater() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a >= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_with_mux() {
    // Use comparison result in a MUX
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(100));

    let source = r#"
        let cmp = a < b
        let r = mux(cmp, 100, 200)
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

// ============================================================================
// L1: Poseidon hash tests for Plonkish backend
// ============================================================================

#[test]
fn test_plonkish_poseidon_single() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);
    let expected = poseidon_hash(&params, left, right);

    let mut inputs = HashMap::new();
    inputs.insert("l".to_string(), left);
    inputs.insert("r".to_string(), right);
    inputs.insert("out".to_string(), expected);

    let source = "assert_eq(poseidon(l, r), out)";
    compile_source(source, &["out"], &["l", "r"], &inputs);
}

#[test]
fn test_plonkish_poseidon_chained() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(10);
    let b = FieldElement::from_u64(20);
    let c = FieldElement::from_u64(30);
    let h1 = poseidon_hash(&params, a, b);
    let expected = poseidon_hash(&params, h1, c);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), a);
    inputs.insert("b".to_string(), b);
    inputs.insert("c".to_string(), c);
    inputs.insert("out".to_string(), expected);

    let source = r#"
        let h = poseidon(a, b)
        assert_eq(poseidon(h, c), out)
    "#;
    compile_source(source, &["out"], &["a", "b", "c"], &inputs);
}

#[test]
fn test_plonkish_poseidon_with_arithmetic() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let x = FieldElement::from_u64(5);
    let y = FieldElement::from_u64(7);
    let prod = x.mul(&y); // 35
    let expected = poseidon_hash(&params, prod, y);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), x);
    inputs.insert("y".to_string(), y);
    inputs.insert("out".to_string(), expected);

    let source = r#"
        let p = x * y
        assert_eq(poseidon(p, y), out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

// ============================================================================
// L2: Negative tests — invalid witnesses must be rejected
// ============================================================================

#[test]
fn test_plonkish_wrong_mul_rejected() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a * b, out)";

    let program = ir::IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(99)); // wrong: 6*7=42

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
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

    let program = ir::IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(20)); // x != y

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
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

    let program = ir::IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("c".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    inputs.insert("out".to_string(), FieldElement::from_u64(99)); // wrong: mux(1,10,20)=10

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
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

    let program = ir::IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ZERO); // wrong: 3 < 7 is true (1)

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "wrong comparison result should be rejected"
    );
}

#[test]
fn test_plonkish_missing_input_error() {
    let program = ir::IrLowering::lower_circuit(
        "assert_eq(x, y)",
        &[],
        &["x", "y"],
    )
    .unwrap();

    let mut compiler = PlonkishCompiler::new();
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
    let program = ir::IrLowering::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("expected".to_string(), FieldElement::ONE); // WRONG

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "claiming 5 == 10 must fail Plonkish verification"
    );
}

#[test]
fn test_plonkish_wrong_poseidon_rejected() {
    let source = "assert_eq(poseidon(l, r), out)";
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["l", "r"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("l".to_string(), FieldElement::from_u64(1));
    inputs.insert("r".to_string(), FieldElement::from_u64(2));
    inputs.insert("out".to_string(), FieldElement::from_u64(12345)); // WRONG

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
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

// ============================================================================
// C1–C4: Malicious prover tests — copy-constrained constants must be tamper-proof
// ============================================================================

use constraints::plonkish::{CellRef, PlonkishError};

/// C1: Corrupting col_d on the IsZero enforce row (d=1→0) must be caught.
#[test]
fn test_c1_forge_is_zero_rejected() {
    let source = "let eq = x == y\nassert_eq(eq, out)";
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("y".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    // Honest witness passes
    compiler.system.verify().expect("honest witness should pass");

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
            compiler.system.assignments.set(col_d, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find an IsZero enforce row to corrupt");
    let err = compiler.system.verify().expect_err("corrupted d=1→0 must fail");
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
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(6));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    compiler.system.verify().expect("honest witness should pass");

    // Corrupt col_d on the inverse row (d=1) to 0
    let col_d = compiler.col_d;
    let col_const = compiler.col_constant;
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        let d_val = compiler.system.assignments.get(col_d, row);
        if const_val == FieldElement::ONE && d_val == FieldElement::ONE {
            compiler.system.assignments.set(col_d, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find a division inverse row to corrupt");
    let err = compiler.system.verify().expect_err("corrupted d=1→0 must fail");
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
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ONE);

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    compiler.system.verify().expect("honest witness should pass");

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
            compiler.system.assignments.set(col_b, row, FieldElement::ZERO);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find a bit coefficient row (2^1) to corrupt");
    let err = compiler.system.verify().expect_err("corrupted 2^i→0 must fail");
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
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(20));
    inputs.insert("y".to_string(), FieldElement::from_u64(22));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    compiler.system.verify().expect("honest witness should pass");

    // Corrupt: find a row where col_b=1 (addition identity) and set it to 2
    let col_b = compiler.col_b;
    let col_const = compiler.col_constant;
    let num_rows = compiler.num_circuit_rows();
    let mut corrupted = false;
    for row in 0..num_rows {
        let const_val = compiler.system.assignments.get(col_const, row);
        let b_val = compiler.system.assignments.get(col_b, row);
        if const_val == FieldElement::ONE && b_val == FieldElement::ONE {
            compiler.system.assignments.set(col_b, row, FieldElement::from_u64(2));
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find an addition identity row to corrupt");
    let err = compiler.system.verify().expect_err("corrupted b=1→2 must fail");
    assert!(
        matches!(err, PlonkishError::CopyConstraintViolation { .. })
            || matches!(err, PlonkishError::GateNotSatisfied { .. }),
        "expected CopyConstraintViolation or GateNotSatisfied, got: {err}"
    );
}

// ============================================================================
// T1: IsLt/IsLe boundary tests near 2^252
// ============================================================================

/// Compute 2^n as a FieldElement.
fn pow2(n: u32) -> FieldElement {
    let mut v = FieldElement::ONE;
    for _ in 0..n {
        v = v.add(&v);
    }
    v
}

#[test]
fn test_plonkish_is_lt_boundary_adjacent_at_max() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let almost = max.sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), almost);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source("let r = a < b\nassert_eq(r, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_is_lt_boundary_equal_zero() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);
    compile_source("let r = a < b\nassert_eq(r, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_is_lt_boundary_zero_vs_max() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source("let r = a < b\nassert_eq(r, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_is_lt_boundary_max_vs_zero() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), max);
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);
    compile_source("let r = a < b\nassert_eq(r, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_is_le_boundary_max_equal() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), max);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source("let r = a <= b\nassert_eq(r, out)", &["out"], &["a", "b"], &inputs);
}

// ============================================================================
// T3: Plonkish boolean enforcement — flag=2 must fail
// ============================================================================

#[test]
fn test_plonkish_mux_non_boolean_flag_rejected() {
    // mux with cond=2 (not boolean) must fail boolean enforcement
    let source = r#"
        let r = mux(c, a, b)
        assert_eq(r, out)
    "#;
    let program = ir::IrLowering::lower_circuit(source, &["out"], &["c", "a", "b"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("c".to_string(), FieldElement::from_u64(2)); // NOT boolean
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    // mux(2, 10, 20) = 2*(10-20)+20 = 2*(-10)+20 = 0 in honest computation
    // but the boolean enforcement c*(1-c)=0 → 2*(1-2)=2*(-1)=-2 ≠ 0
    inputs.insert("out".to_string(), FieldElement::ZERO);

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "mux with flag=2 must fail boolean enforcement in Plonkish"
    );
}

#[test]
fn test_plonkish_assert_non_boolean_rejected() {
    // assert(x) with x=2 must fail boolean enforcement
    let source = "assert(x)";
    let program = ir::IrLowering::lower_circuit(source, &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(2)); // NOT boolean

    wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "assert(2) must fail boolean enforcement in Plonkish"
    );
}
