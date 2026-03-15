//! Plonkish Cross-Validation — Levels 1 & 3
//!
//! Level 1: Cross-backend consistency — same circuit compiled to R1CS and Plonkish
//!          must produce identical output values.
//! Level 3: JSON export re-evaluation — export Plonkish to JSON, parse back,
//!          re-evaluate all gates and copy constraints independently.
//!
//! These tests verify that the Plonkish backend produces the same results as the
//! R1CS backend (which is already cross-validated against snarkjs).

use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use compiler::r1cs_backend::R1CSCompiler;
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

/// Compile a circuit via R1CS, return the witness (for output value extraction).
fn compile_r1cs(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> Vec<FieldElement> {
    let mut program = IrLowering::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness_vec = compiler
        .compile_ir_with_witness(&program, inputs)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness_vec)
        .expect("R1CS verification failed");
    witness_vec
}

/// Compile a circuit via Plonkish, verify, return the system for inspection.
fn compile_plonkish(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let mut program = IrLowering::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir(&program)
        .expect("Plonkish compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inputs, &mut compiler.system.assignments)
        .expect("Plonkish witness gen failed");
    compiler
        .system
        .verify()
        .expect("Plonkish verification failed");
    compiler
}

/// Get the output value from R1CS witness. Wire[1] = first public input.
fn r1cs_output(witness: &[FieldElement]) -> FieldElement {
    witness[1]
}

/// Get the output value from Plonkish. Instance column, row 0.
fn plonkish_output(compiler: &PlonkishCompiler) -> FieldElement {
    compiler.system.assignments.get(compiler.col_instance, 0)
}

/// Build inputs map from pairs.
fn make_inputs(pairs: &[(&str, FieldElement)]) -> HashMap<String, FieldElement> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

// ============================================================================
// LEVEL 1: Cross-backend consistency — R1CS vs Plonkish same outputs
// ============================================================================

#[test]
fn cross_backend_mul() {
    let inputs = make_inputs(&[("out", fe(42)), ("a", fe(6)), ("b", fe(7))]);
    let r1cs = compile_r1cs("assert_eq(a * b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a * b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Mul: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_div() {
    let inputs = make_inputs(&[("out", fe(6)), ("a", fe(42)), ("b", fe(7))]);
    let r1cs = compile_r1cs("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Div: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_mux() {
    let inputs = make_inputs(&[("out", fe(10)), ("c", fe(1)), ("a", fe(10)), ("b", fe(20))]);
    let r1cs = compile_r1cs(
        "assert_eq(mux(c, a, b), out)",
        &["out"],
        &["c", "a", "b"],
        &inputs,
    );
    let plonk = compile_plonkish(
        "assert_eq(mux(c, a, b), out)",
        &["out"],
        &["c", "a", "b"],
        &inputs,
    );

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Mux: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_poseidon_1_2() {
    let expected =
        fe_str("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    let inputs = make_inputs(&[("expected", expected), ("a", fe(1)), ("b", fe(2))]);
    let source = "let h = poseidon(a, b)\nassert_eq(h, expected)";

    let r1cs = compile_r1cs(source, &["expected"], &["a", "b"], &inputs);
    let plonk = compile_plonkish(source, &["expected"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Poseidon(1,2): R1CS and Plonkish outputs must match"
    );
    // Both must match the industry golden vector
    assert_eq!(
        r1cs_output(&r1cs),
        expected,
        "Poseidon(1,2) must match circomlibjs golden vector"
    );
}

#[test]
fn cross_backend_poseidon_0_0() {
    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, FieldElement::ZERO, FieldElement::ZERO);
    let inputs = make_inputs(&[("expected", expected), ("a", fe(0)), ("b", fe(0))]);
    let source = "let h = poseidon(a, b)\nassert_eq(h, expected)";

    let r1cs = compile_r1cs(source, &["expected"], &["a", "b"], &inputs);
    let plonk = compile_plonkish(source, &["expected"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Poseidon(0,0): R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_iseq() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(5)), ("b", fe(5))]);
    let r1cs = compile_r1cs("assert_eq(a == b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a == b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "IsEq: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_isneq() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(5)), ("b", fe(3))]);
    let r1cs = compile_r1cs("assert_eq(a != b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a != b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "IsNeq: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_bool_and() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(1)), ("b", fe(1))]);
    let r1cs = compile_r1cs("assert_eq(a && b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a && b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "And: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_bool_or() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(0)), ("b", fe(1))]);
    let r1cs = compile_r1cs("assert_eq(a || b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a || b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Or: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_field_inverse() {
    // 1/2 = (p+1)/2 — non-trivial field result
    let inv2 =
        fe_str("10944121435919637611123202872628637544274182200208017171849102093287904247809");
    let inputs = make_inputs(&[("out", inv2), ("a", fe(1)), ("b", fe(2))]);
    let r1cs = compile_r1cs("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);
    let plonk = compile_plonkish("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Field inverse 1/2: R1CS and Plonkish outputs must match"
    );
}

#[test]
fn cross_backend_complex_circuit() {
    // (a + b) * c - d = out: ((2+3)*4)-5 = 15
    let inputs = make_inputs(&[
        ("out", fe(15)),
        ("a", fe(2)),
        ("b", fe(3)),
        ("c", fe(4)),
        ("d", fe(5)),
    ]);
    let source = "assert_eq((a + b) * c - d, out)";
    let r1cs = compile_r1cs(source, &["out"], &["a", "b", "c", "d"], &inputs);
    let plonk = compile_plonkish(source, &["out"], &["a", "b", "c", "d"], &inputs);

    assert_eq!(
        r1cs_output(&r1cs),
        plonkish_output(&plonk),
        "Complex circuit: R1CS and Plonkish outputs must match"
    );
}

// ============================================================================
// LEVEL 3: JSON export re-evaluation
// Export Plonkish to JSON, parse back, verify all gates and copies.
// ============================================================================

#[test]
fn json_roundtrip_mul() {
    let inputs = make_inputs(&[("out", fe(42)), ("a", fe(6)), ("b", fe(7))]);
    let compiler = compile_plonkish("assert_eq(a * b, out)", &["out"], &["a", "b"], &inputs);

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("JSON validation failed");

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "achronyme-plonkish-v1");
    assert!(parsed["num_rows"].as_u64().unwrap() > 0);
    assert!(parsed["gates"].as_array().unwrap().len() > 0);
    assert!(parsed["copies"].as_array().unwrap().len() > 0);
}

#[test]
fn json_roundtrip_poseidon() {
    let expected =
        fe_str("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    let inputs = make_inputs(&[("expected", expected), ("a", fe(1)), ("b", fe(2))]);
    let compiler = compile_plonkish(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &inputs,
    );

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("Poseidon JSON validation failed");

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "achronyme-plonkish-v1");
    let num_rows = parsed["num_rows"].as_u64().unwrap();
    assert!(
        num_rows > 100,
        "Poseidon should use >100 rows, got {num_rows}"
    );
}

#[test]
fn json_roundtrip_mux() {
    let inputs = make_inputs(&[("out", fe(10)), ("c", fe(1)), ("a", fe(10)), ("b", fe(20))]);
    let compiler = compile_plonkish(
        "assert_eq(mux(c, a, b), out)",
        &["out"],
        &["c", "a", "b"],
        &inputs,
    );

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("Mux JSON validation failed");
}

#[test]
fn json_roundtrip_div() {
    let inputs = make_inputs(&[("out", fe(6)), ("a", fe(42)), ("b", fe(7))]);
    let compiler = compile_plonkish("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("Div JSON validation failed");
}

#[test]
fn json_roundtrip_iseq() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(5)), ("b", fe(5))]);
    let compiler = compile_plonkish("assert_eq(a == b, out)", &["out"], &["a", "b"], &inputs);

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("IsEq JSON validation failed");
}

#[test]
fn json_roundtrip_bool_ops() {
    let inputs = make_inputs(&[("out", fe(1)), ("a", fe(1)), ("b", fe(1))]);
    let compiler = compile_plonkish("assert_eq(a && b, out)", &["out"], &["a", "b"], &inputs);

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("Bool ops JSON validation failed");
}

#[test]
fn json_assignments_match_system() {
    // Verify that the JSON assignments array matches what PlonkishSystem has
    let inputs = make_inputs(&[("out", fe(42)), ("a", fe(6)), ("b", fe(7))]);
    let compiler = compile_plonkish("assert_eq(a * b, out)", &["out"], &["a", "b"], &inputs);

    let json = constraints::write_plonkish_json(&compiler.system);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Instance column should contain the public output
    let instance = &parsed["assignments"]["instance"];
    let first_col = instance
        .as_array()
        .unwrap()
        .first()
        .unwrap()
        .as_array()
        .unwrap();
    // Find 42 in instance values
    let has_42 = first_col.iter().any(|v| v.as_str() == Some("42"));
    assert!(has_42, "instance column should contain public output 42");
}
