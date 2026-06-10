use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::{WitnessError, WitnessGenerator};

/// Helper: build compiler via IR pipeline, generate witness, verify.
fn compile_and_verify(public: &[(&str, u64)], witness: &[(&str, u64)], source: &str) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&rc);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }

    let w = gen.generate(&inputs).unwrap();
    rc.cs.verify(&w).unwrap();
}

/// Helper with FieldElement inputs (for poseidon tests with non-u64 values).
fn compile_and_verify_fe(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&rc);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    rc.cs.verify(&w).unwrap();
}

// ====================================================================
// Test 1: Simple multiplication
// ====================================================================

#[test]
fn test_simple_multiply_witness() {
    // Circuit: a * b, assert_eq(a * b, out)
    // a=6, b=7, out=42
    compile_and_verify(
        &[("out", 42)],
        &[("a", 6), ("b", 7)],
        "assert_eq(a * b, out)",
    );
}

// ====================================================================
// Test 2: Addition — no witness ops (all linear)
// ====================================================================

#[test]
fn test_addition_no_ops() {
    // Circuit: 3*a + 2*b = out → all linear, 0 witness ops
    let program = IrLowering::<Bn254Fr>::lower_circuit(
        "assert_eq(3 * a + 2 * b, out)",
        &["out"],
        &["a", "b"],
    )
    .unwrap();

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();

    assert_eq!(
        rc.witness_ops.len(),
        0,
        "linear ops should produce 0 witness ops"
    );

    let gen = WitnessGenerator::from_compiler(&rc);
    let mut inputs = HashMap::new();
    // a=4, b=5 → 3*4 + 2*5 = 22
    inputs.insert("a".into(), FieldElement::from_u64(4));
    inputs.insert("b".into(), FieldElement::from_u64(5));
    inputs.insert("out".into(), FieldElement::from_u64(22));

    let w = gen.generate(&inputs).unwrap();
    rc.cs.verify(&w).unwrap();
}

// ====================================================================
// Test 3: Quadratic — x^2 + x + 5 = out
// ====================================================================

#[test]
fn test_quadratic_witness() {
    // x=5 → x^2 + x + 5 = 25 + 5 + 5 = 35
    compile_and_verify(&[("out", 35)], &[("x", 5)], "assert_eq(x ^ 2 + x + 5, out)");
}

// ====================================================================
// Test 4: Let chain — x*x → x2*x → assert_eq
// ====================================================================

#[test]
fn test_let_chain_witness() {
    // x=3 → x2=9, x3=27
    compile_and_verify(
        &[("out", 27)],
        &[("x", 3)],
        r#"
        let x2 = x * x
        let x3 = x2 * x
        assert_eq(x3, out)
        "#,
    );
}

// ====================================================================
// Test 5: Division — a / b = out
// ====================================================================

#[test]
fn test_division_witness() {
    // a=42, b=7 → a/b = 6
    compile_and_verify(
        &[("out", 6)],
        &[("a", 42), ("b", 7)],
        "assert_eq(a / b, out)",
    );
}

// ====================================================================
// Test 6: MUX — flag=1 → selects a
// ====================================================================

#[test]
fn test_mux_flag_one_witness() {
    // mux(1, a, b) = a when flag=1
    compile_and_verify(
        &[("out", 10)],
        &[("flag", 1), ("a", 10), ("b", 20)],
        "assert_eq(mux(flag, a, b), out)",
    );
}

// ====================================================================
// Test 7: MUX — flag=0 → selects b
// ====================================================================

#[test]
fn test_mux_flag_zero_witness() {
    // mux(0, a, b) = b when flag=0
    compile_and_verify(
        &[("out", 20)],
        &[("flag", 0), ("a", 10), ("b", 20)],
        "assert_eq(mux(flag, a, b), out)",
    );
}

// ====================================================================
// Test 8: Poseidon hash — single call
// ====================================================================

#[test]
fn test_poseidon_witness() {
    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);
    let expected = poseidon_hash(&params, left, right);

    compile_and_verify_fe(
        &[("out", expected)],
        &[("left", left), ("right", right)],
        "assert_eq(poseidon(left, right), out)",
    );
}

// ====================================================================
// Test 9: Chained Poseidon — poseidon(poseidon(a, b), c)
// ====================================================================

#[test]
fn test_chained_poseidon_witness() {
    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(10);
    let b = FieldElement::from_u64(20);
    let c = FieldElement::from_u64(30);
    let inner = poseidon_hash(&params, a, b);
    let expected = poseidon_hash(&params, inner, c);

    compile_and_verify_fe(
        &[("out", expected)],
        &[("a", a), ("b", b), ("c", c)],
        "assert_eq(poseidon(poseidon(a, b), c), out)",
    );
}

// ====================================================================
// Test 10: Merkle path depth-1 — mux + poseidon + assert_eq
// ====================================================================

#[test]
fn test_merkle_path_witness() {
    // Depth-1 Merkle proof:
    //   leaf, sibling, direction (0=left, 1=right)
    //   left  = mux(dir, sibling, leaf)
    //   right = mux(dir, leaf, sibling)
    //   root  = poseidon(left, right)
    let params = PoseidonParams::bn254_t3();
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);

    // Direction = 0 → leaf is on the left
    let expected = poseidon_hash(&params, leaf, sibling);

    compile_and_verify_fe(
        &[("root", expected)],
        &[
            ("leaf", leaf),
            ("sibling", sibling),
            ("dir", FieldElement::ZERO),
        ],
        r#"
        let l = mux(dir, sibling, leaf)
        let r = mux(dir, leaf, sibling)
        assert_eq(poseidon(l, r), root)
        "#,
    );
}

// ====================================================================
// Test 11: For loop — unrolled accumulation
// ====================================================================

#[test]
fn test_for_loop_witness() {
    // acc = x
    // for i in 0..3 { acc = acc * x }
    // → acc = x^4
    // x=2 → x^4 = 16
    compile_and_verify(
        &[("out", 16)],
        &[("x", 2)],
        r#"
        let acc = x
        let acc = acc * x
        let acc = acc * x
        let acc = acc * x
        assert_eq(acc, out)
        "#,
    );
}

#[test]
fn test_for_loop_unrolled_witness() {
    // x^4 via for loop (each iteration: x * x → shadowed let)
    // Actually: let's use accumulation pattern via for + let rebinding
    // for i in 0..3 → 3 extra multiplications: x * x * x * x = x^4
    // x=2 → 16
    compile_and_verify(&[("out", 32)], &[("x", 2)], "assert_eq(x ^ 5, out)");
}

// ====================================================================
// Test 12: Missing input → WitnessError::MissingInput
// ====================================================================

#[test]
fn test_missing_input_error() {
    let program =
        IrLowering::<Bn254Fr>::lower_circuit("assert_eq(a * b, out)", &["out"], &["a", "b"])
            .unwrap();

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&rc);

    // Only provide 'a', missing 'out' and 'b'
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(6));

    let err = gen.generate(&inputs).unwrap_err();
    match err {
        WitnessError::MissingInput(name) => {
            assert_eq!(name, "out"); // public inputs checked first
        }
        other => panic!("expected MissingInput, got: {other}"),
    }
}

// ====================================================================
// Test 13: Witness ops count
// ====================================================================

#[test]
fn test_witness_ops_count() {
    // a * b → 1 Multiply op
    let program = IrLowering::<Bn254Fr>::lower_circuit("a * b", &[], &["a", "b"]).unwrap();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.witness_ops.len(), 1);

    // a / b → 1 Inverse + 1 Multiply = 2 ops
    let program = IrLowering::<Bn254Fr>::lower_circuit("a / b", &[], &["a", "b"]).unwrap();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.witness_ops.len(), 2);
}

// ====================================================================
// skip_eval_validation: skipping early validation must not change the
// produced witness, and a missing input must still error (not panic).
// ====================================================================

#[test]
fn skip_eval_validation_produces_identical_witness() {
    // Exercises a Multiply witness op plus an Inverse via the division.
    let program =
        IrLowering::<Bn254Fr>::lower_circuit("assert_eq(a * b, c / d)", &["c", "d"], &["a", "b"])
            .unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(84));
    inputs.insert("d".to_string(), FieldElement::from_u64(2));

    let mut rc_validated = R1CSCompiler::<Bn254Fr>::new();
    let w_validated = rc_validated
        .compile_ir_with_witness(&program, &inputs)
        .unwrap();

    let mut rc_skipped = R1CSCompiler::<Bn254Fr>::new();
    rc_skipped.set_skip_eval_validation(true);
    let w_skipped = rc_skipped
        .compile_ir_with_witness(&program, &inputs)
        .unwrap();

    assert_eq!(
        w_validated, w_skipped,
        "witness must be identical with and without early validation"
    );
    assert!(rc_validated.cs.verify(&w_validated).is_ok());
    assert!(rc_skipped.cs.verify(&w_skipped).is_ok());
}

#[test]
fn skip_eval_validation_missing_input_errors_without_panic() {
    let program =
        IrLowering::<Bn254Fr>::lower_circuit("assert_eq(a * b, out)", &["out"], &["a", "b"])
            .unwrap();

    // `b` is absent — with early validation skipped, the witness fill must
    // return an error rather than panic on the missing key.
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_skip_eval_validation(true);
    let result = rc.compile_ir_with_witness(&program, &inputs);
    assert!(result.is_err(), "missing input must error, not panic");
}

#[test]
fn skip_eval_validation_violating_input_caught_by_verify() {
    // With early validation skipped, a constraint-violating witness is no
    // longer rejected up front. The downstream `cs.verify` is the safety net
    // that callers rely on when they set the skip flag (e.g. `prove_r1cs`).
    let program =
        IrLowering::<Bn254Fr>::lower_circuit("assert_eq(a * b, c)", &["c"], &["a", "b"]).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(99)); // 6 * 7 = 42 != 99

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_skip_eval_validation(true);
    // Builds without error — there is no eval pass to reject the bad input.
    let witness = rc.compile_ir_with_witness(&program, &inputs).unwrap();
    assert!(
        rc.cs.verify(&witness).is_err(),
        "cs.verify must reject the violating witness when eval is skipped"
    );
}

#[test]
fn split_fill_matches_fused_compile_and_witness() {
    // The prove flow runs emission and the witness fill as separate calls so
    // it can drop the IR program in between. The split path must produce a
    // witness bit-identical to the fused entry point.
    let source = "assert_eq(a * b + a, c)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["c"], &["a", "b"]).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(48));

    let mut fused = R1CSCompiler::<Bn254Fr>::new();
    let fused_witness = fused.compile_ir_with_witness(&program, &inputs).unwrap();

    let mut split = R1CSCompiler::<Bn254Fr>::new();
    split.compile_ir(&program).unwrap();
    // Dropping the emission lookup state must not affect the fill: the
    // replay reads only the recorded witness ops.
    split.release_emission_state();
    let split_witness = split.fill_witness(&inputs).unwrap();

    assert_eq!(fused_witness, split_witness);
    fused.cs.verify(&fused_witness).unwrap();
    split.cs.verify(&split_witness).unwrap();
}

#[test]
fn split_flow_survives_optimize_and_substitution_fixup() {
    // Production prove order: emit, shed emission state, fill, optimize,
    // re-derive substituted wires, verify.
    let source = "assert_eq(a * b + a, c)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["c"], &["a", "b"]).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(5));
    inputs.insert("c".to_string(), FieldElement::from_u64(18));

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).unwrap();
    rc.release_emission_state();
    let mut witness = rc.fill_witness(&inputs).unwrap();

    let pre = rc.cs.num_constraints();
    rc.optimize_r1cs();
    assert!(
        rc.cs.num_constraints() < pre,
        "linear elimination is expected to make progress on this circuit"
    );
    if let Some(subs) = &rc.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    rc.cs.verify(&witness).unwrap();

    // Proof generation runs on the constraint system alone; consuming the
    // compiler must hand back a system the witness still satisfies.
    let cs = rc.into_constraint_system();
    cs.verify(&witness).unwrap();
}
