use compiler::r1cs_backend::R1CSCompiler;
use compiler::r1cs_error::R1CSError;
use memory::FieldElement;

// ====================================================================
// Poseidon builtin tests
// ====================================================================

#[test]
fn test_poseidon_constraint_count() {
    // poseidon(a, b) with simple variables → 360 permutation + 1 capacity = 361
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("poseidon(a, b)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 361);
}

#[test]
fn test_poseidon_chained() {
    // poseidon(poseidon(a, b), c) → (360+1) + (360+1) = 722 constraints
    // Inner poseidon returns a Variable, so outer's left materialization is free
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.compile_circuit("poseidon(poseidon(a, b), c)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 722);
}

#[test]
fn test_poseidon_in_loop() {
    // for i in 0..2 { poseidon(a, b) } → 2 * 361 = 722
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("for i in 0..2 { poseidon(a, b) }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 722);
}

#[test]
fn test_poseidon_with_expression_args() {
    // poseidon(a + b, c * d)
    // a + b → LC (needs materialization: 1 constraint)
    // c * d → mul_lc returns LC::from_variable (no materialization needed)
    // poseidon: 361 constraints (360 permutation + 1 capacity)
    // Total: 1 (materialize a+b) + 1 (c*d mul) + 361 = 363
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.declare_witness("d");
    rc.compile_circuit("poseidon(a + b, c * d)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 363);
}

#[test]
fn test_poseidon_constant_arg_materialization() {
    // poseidon(5, a) → constant 5 must be materialized (1 constraint) + 361
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("poseidon(5, a)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 362);
}

#[test]
fn test_poseidon_wrong_arg_count_too_few() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    let err = rc.compile_circuit("poseidon(a)").unwrap_err();
    match err {
        R1CSError::WrongArgumentCount {
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
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    let err = rc.compile_circuit("poseidon(a, b, c)").unwrap_err();
    assert!(matches!(
        err,
        R1CSError::WrongArgumentCount {
            expected: 2,
            got: 3,
            ..
        }
    ));
}

// ====================================================================
// Mux builtin tests
// ====================================================================

#[test]
fn test_mux_constraint_count() {
    // mux(flag, a, b) → 1 boolean check + 1 MUX mul = 2 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("mux(flag, a, b)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_mux_selects_first_when_flag_one() {
    // mux(flag, a, b) with flag=1 → result = a = 42
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("assert_eq(mux(flag, a, b), out)")
        .unwrap();

    // 2 (mux) + 1 (assert_eq) = 3
    assert_eq!(rc.cs.num_constraints(), 3);

    // flag=1, a=42, b=99: result = a = 42
    // mux computes: flag * (a - b) = 1 * (42 - 99) = 42 - 99 in field
    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let diff = a_val.sub(&b_val);
    let mux_prod = FieldElement::ONE.mul(&diff); // flag * (a - b)

    // Wire layout: ONE, out, flag, a, b, mux_product
    let witness = vec![
        FieldElement::ONE,
        a_val,             // out = 42 (selected a)
        FieldElement::ONE, // flag = 1
        a_val,             // a = 42
        b_val,             // b = 99
        mux_prod,          // flag * (a - b)
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_mux_selects_second_when_flag_zero() {
    // mux(flag, a, b) with flag=0 → result = b = 99
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("assert_eq(mux(flag, a, b), out)")
        .unwrap();

    // Wire layout: ONE, out, flag, a, b, mux_product
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(99), // out = 99 (selected b)
        FieldElement::ZERO,         // flag = 0
        FieldElement::from_u64(42), // a
        FieldElement::from_u64(99), // b
        FieldElement::ZERO,         // flag * (a - b) = 0
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_mux_boolean_enforcement() {
    // mux with flag=2 should fail (boolean check: 2*(1-2) = -2 ≠ 0)
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("assert_eq(mux(flag, a, b), out)")
        .unwrap();

    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let flag_val = FieldElement::from_u64(2);
    let diff = a_val.sub(&b_val);
    let mux_prod = flag_val.mul(&diff);
    let result = mux_prod.add(&b_val);

    let witness = vec![
        FieldElement::ONE,
        result,   // out
        flag_val, // flag = 2 (invalid!)
        a_val,
        b_val,
        mux_prod, // 2 * (a - b)
    ];
    assert!(
        rc.cs.verify(&witness).is_err(),
        "flag=2 should fail boolean enforcement"
    );
}

#[test]
fn test_mux_with_complex_branches() {
    // mux(flag, a * b, c + d) → 1 mul (a*b) + 2 mux = 3
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.declare_witness("d");
    rc.compile_circuit("mux(flag, a * b, c + d)").unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_mux_wrong_arg_count_too_few() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    let err = rc.compile_circuit("mux(a, b)").unwrap_err();
    match err {
        R1CSError::WrongArgumentCount {
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
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.declare_witness("d");
    let err = rc.compile_circuit("mux(a, b, c, d)").unwrap_err();
    assert!(matches!(
        err,
        R1CSError::WrongArgumentCount {
            expected: 3,
            got: 4,
            ..
        }
    ));
}

// ====================================================================
// assert_eq error migration test
// ====================================================================

#[test]
fn test_assert_eq_wrong_arg_count() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    let err = rc.compile_circuit("assert_eq(a)").unwrap_err();
    match err {
        R1CSError::WrongArgumentCount {
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
    // Total: 365
    let mut rc = R1CSCompiler::new();
    rc.declare_public("expected_root");
    rc.declare_witness("leaf");
    rc.declare_witness("sibling");
    rc.declare_witness("bit");

    rc.compile_circuit(
        "let left = mux(bit, sibling, leaf); \
         let right = mux(bit, leaf, sibling); \
         let root_hash = poseidon(left, right); \
         assert_eq(root_hash, expected_root)",
    )
    .unwrap();

    // mux left: 2 (boolean + mul)
    // mux right: 2 (boolean + mul)
    // poseidon: 361 (360 permutation + 1 capacity)
    // assert_eq: 1
    //
    // Note: mux returns an LC (selected + else), not a single variable.
    // When passed to poseidon, each mux result needs materialization (1 constraint each).
    // So: 2 + 2 + 2 (materialization) + 361 + 1 = 368
    assert_eq!(rc.cs.num_constraints(), 368);
}
