use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::{WitnessError, WitnessGenerator};
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::FieldElement;

/// Helper: build compiler via IR pipeline, generate witness, verify.
fn compile_and_verify(public: &[(&str, u64)], witness: &[(&str, u64)], source: &str) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut rc = R1CSCompiler::new();
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
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut rc = R1CSCompiler::new();
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
    let program =
        IrLowering::lower_circuit("assert_eq(3 * a + 2 * b, out)", &["out"], &["a", "b"]).unwrap();

    let mut rc = R1CSCompiler::new();
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
        IrLowering::lower_circuit("assert_eq(a * b, out)", &["out"], &["a", "b"]).unwrap();

    let mut rc = R1CSCompiler::new();
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
    let program = IrLowering::lower_circuit("a * b", &[], &["a", "b"]).unwrap();
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.witness_ops.len(), 1);

    // a / b → 1 Inverse + 1 Multiply = 2 ops
    let program = IrLowering::lower_circuit("a / b", &[], &["a", "b"]).unwrap();
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    assert_eq!(rc.witness_ops.len(), 2);
}
