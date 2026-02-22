use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::error::IrError;
use ir::IrLowering;
use memory::FieldElement;

// ====================================================================
// Poseidon builtin tests
// ====================================================================

#[test]
fn test_poseidon_constraint_count() {
    // poseidon(a, b) with simple variables → 360 permutation + 1 capacity + 1 assert_eq = 362
    let mut program =
        IrLowering::lower_circuit("assert_eq(poseidon(a, b), out)", &["out"], &["a", "b"])
            .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 362);
}

#[test]
fn test_poseidon_chained() {
    // poseidon(poseidon(a, b), c) → 2 * 361 + 1 assert_eq = 723
    let mut program = IrLowering::lower_circuit(
        "assert_eq(poseidon(poseidon(a, b), c), out)",
        &["out"],
        &["a", "b", "c"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 723);
}

#[test]
fn test_poseidon_in_loop() {
    // Two poseidon calls via loop, last result asserted → 2 * 361 + 1 assert_eq = 723
    let mut program = IrLowering::lower_circuit(
        "let h = poseidon(a, b)\nlet h = poseidon(h, b)\nassert_eq(h, out)",
        &["out"],
        &["a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 723);
}

#[test]
fn test_poseidon_with_expression_args() {
    // poseidon(a + b, c * d) with assert_eq
    // a + b → LC (needs materialization: 1 constraint)
    // c * d → mul_lc returns LC::from_variable (no materialization needed)
    // poseidon: 361 constraints (360 permutation + 1 capacity)
    // assert_eq: 1 constraint
    // Total: 1 (materialize a+b) + 1 (c*d mul) + 361 + 1 = 364
    let mut program = IrLowering::lower_circuit(
        "assert_eq(poseidon(a + b, c * d), out)",
        &["out"],
        &["a", "b", "c", "d"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 364);
}

#[test]
fn test_poseidon_constant_arg_materialization() {
    // poseidon(5, a) with assert_eq → constant 5 must be materialized (1 constraint) + 361 + 1
    let mut program =
        IrLowering::lower_circuit("assert_eq(poseidon(5, a), out)", &["out"], &["a"]).unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 363);
}

#[test]
fn test_poseidon_wrong_arg_count_too_few() {
    let err = IrLowering::lower_circuit("poseidon(a)", &[], &["a"]).unwrap_err();
    match err {
        IrError::WrongArgumentCount {
            builtin,
            expected,
            got,
            ..
        } => {
            assert_eq!(builtin, "poseidon");
            assert_eq!(expected, 2);
            assert_eq!(got, 1);
        }
        _ => panic!("expected WrongArgumentCount, got: {err}"),
    }
}

#[test]
fn test_poseidon_wrong_arg_count_too_many() {
    let err =
        IrLowering::lower_circuit("poseidon(a, b, c)", &[], &["a", "b", "c"]).unwrap_err();
    match err {
        IrError::WrongArgumentCount {
            builtin,
            expected,
            got,
            ..
        } => {
            assert_eq!(builtin, "poseidon");
            assert_eq!(expected, 2);
            assert_eq!(got, 3);
        }
        _ => panic!("expected WrongArgumentCount, got: {err}"),
    }
}

// ====================================================================
// Mux builtin tests
// ====================================================================

#[test]
fn test_mux_constraint_count() {
    // mux(flag, a, b) with assert_eq → 1 boolean check + 1 MUX mul + 1 assert_eq = 3
    let mut program = IrLowering::lower_circuit(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_mux_selects_first_when_flag_one() {
    // mux(flag, a, b) with flag=1 → result = a = 42
    let mut program = IrLowering::lower_circuit(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));
    let witness = rc.compile_ir_with_witness(&program, &inputs).unwrap();

    // 2 (mux) + 1 (assert_eq) = 3
    assert_eq!(rc.cs.num_constraints(), 3);
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_mux_selects_second_when_flag_zero() {
    // mux(flag, a, b) with flag=0 → result = b = 99
    let mut program = IrLowering::lower_circuit(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(99));
    inputs.insert("flag".to_string(), FieldElement::ZERO);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));
    let witness = rc.compile_ir_with_witness(&program, &inputs).unwrap();

    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_mux_boolean_enforcement() {
    // mux with flag=2 should fail (boolean check: 2*(1-2) = -2 ≠ 0)
    //
    // We cannot use compile_ir_with_witness here because the IR evaluator
    // rejects non-boolean mux conditions. Instead, compile via compile_ir,
    // build a witness with WitnessGenerator using flag=2, and verify that
    // the R1CS constraint system rejects the witness.
    let mut program = IrLowering::lower_circuit(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&rc);

    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let flag_val = FieldElement::from_u64(2);
    // mux(2, 42, 99) = 2*(42-99) + 99 = result
    let diff = a_val.sub(&b_val);
    let mux_prod = flag_val.mul(&diff);
    let result = mux_prod.add(&b_val);

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), result);
    inputs.insert("flag".to_string(), flag_val);
    inputs.insert("a".to_string(), a_val);
    inputs.insert("b".to_string(), b_val);
    let witness = wg.generate(&inputs).unwrap();

    assert!(
        rc.cs.verify(&witness).is_err(),
        "flag=2 should fail boolean enforcement"
    );
}

#[test]
fn test_mux_with_complex_branches() {
    // mux(flag, a * b, c + d) with assert_eq → 1 mul (a*b) + 2 mux + 1 assert_eq = 4
    let mut program = IrLowering::lower_circuit(
        "assert_eq(mux(flag, a * b, c + d), out)",
        &["out"],
        &["flag", "a", "b", "c", "d"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.cs.num_constraints(), 4);
}

#[test]
fn test_mux_wrong_arg_count_too_few() {
    let err = IrLowering::lower_circuit("mux(a, b)", &[], &["a", "b"]).unwrap_err();
    match err {
        IrError::WrongArgumentCount {
            builtin,
            expected,
            got,
            ..
        } => {
            assert_eq!(builtin, "mux");
            assert_eq!(expected, 3);
            assert_eq!(got, 2);
        }
        _ => panic!("expected WrongArgumentCount, got: {err}"),
    }
}

#[test]
fn test_mux_wrong_arg_count_too_many() {
    let err =
        IrLowering::lower_circuit("mux(a, b, c, d)", &[], &["a", "b", "c", "d"]).unwrap_err();
    match err {
        IrError::WrongArgumentCount {
            builtin,
            expected,
            got,
            ..
        } => {
            assert_eq!(builtin, "mux");
            assert_eq!(expected, 3);
            assert_eq!(got, 4);
        }
        _ => panic!("expected WrongArgumentCount, got: {err}"),
    }
}

// ====================================================================
// assert_eq error migration test
// ====================================================================

#[test]
fn test_assert_eq_wrong_arg_count() {
    let err = IrLowering::lower_circuit("assert_eq(a)", &[], &["a"]).unwrap_err();
    match err {
        IrError::WrongArgumentCount {
            builtin,
            expected,
            got,
            ..
        } => {
            assert_eq!(builtin, "assert_eq");
            assert_eq!(expected, 2);
            assert_eq!(got, 1);
        }
        _ => panic!("expected WrongArgumentCount, got: {err}"),
    }
}

// ====================================================================
// Composition test — Merkle-like pattern
// ====================================================================

#[test]
fn test_merkle_path_composition() {
    // Simulates a depth-1 Merkle path verification:
    // let left = mux(bit, sibling, leaf)       → 2 constraints
    // let right = mux(bit, leaf, sibling)      → 2 constraints
    // let root_hash = poseidon(left, right)     → 360 constraints
    // assert_eq(root_hash, expected_root)       → 1 constraint
    let mut program = IrLowering::lower_circuit(
        "let left = mux(bit, sibling, leaf); \
         let right = mux(bit, leaf, sibling); \
         let root_hash = poseidon(left, right); \
         assert_eq(root_hash, expected_root)",
        &["expected_root"],
        &["leaf", "sibling", "bit"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    // 2 (mux left: boolean enforcement + mul)
    // 2 (mux right: boolean enforcement + mul)
    // 2 (materialization of each mux result for poseidon inputs)
    // 361 (poseidon: 360 permutation + 1 capacity)
    // 1 (assert_eq)
    // Total: 368
    assert_eq!(rc.cs.num_constraints(), 368);
}
