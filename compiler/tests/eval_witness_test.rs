use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrLowering;
use memory::FieldElement;

/// Helper: compare witness vectors from old path (compile_ir + WitnessGenerator)
/// and new path (compile_ir_with_witness) for a given circuit and inputs.
fn assert_witness_equivalence(
    pub_decls: &[&str],
    wit_decls: &[&str],
    source: &str,
    inputs: &HashMap<String, FieldElement>,
) {
    let mut program = IrLowering::lower_circuit(source, pub_decls, wit_decls).unwrap();
    ir::passes::optimize(&mut program);

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    // Old path: compile_ir + WitnessGenerator
    let mut c1 = R1CSCompiler::new();
    c1.set_proven_boolean(proven.clone());
    c1.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&c1);
    let w1 = wg.generate(inputs).unwrap();
    c1.cs.verify(&w1).unwrap();

    // New path: compile_ir_with_witness
    let mut c2 = R1CSCompiler::new();
    c2.set_proven_boolean(proven);
    let w2 = c2.compile_ir_with_witness(&program, inputs).unwrap();
    c2.cs.verify(&w2).unwrap();

    assert_eq!(
        w1.len(),
        w2.len(),
        "witness length mismatch: old={} new={}",
        w1.len(),
        w2.len()
    );
    assert_eq!(w1, w2, "witness mismatch between old and new paths");
}

fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}

fn make_inputs(pairs: &[(&str, u64)]) -> HashMap<String, FieldElement> {
    pairs.iter().map(|(n, v)| (n.to_string(), fe(*v))).collect()
}

fn make_inputs_fe(pairs: &[(&str, FieldElement)]) -> HashMap<String, FieldElement> {
    pairs.iter().map(|(n, v)| (n.to_string(), *v)).collect()
}

// ============================================================================
// Equivalence tests
// ============================================================================

#[test]
fn equiv_simple_arithmetic() {
    let inputs = make_inputs(&[("x", 3), ("y", 7), ("out", 10)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let sum = x + y\nassert_eq(out, sum)",
        &inputs,
    );
}

#[test]
fn equiv_multiplication() {
    let inputs = make_inputs(&[("x", 6), ("y", 7), ("out", 42)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let p = x * y\nassert_eq(out, p)",
        &inputs,
    );
}

#[test]
fn equiv_division() {
    let inputs = make_inputs(&[("x", 42), ("y", 6), ("out", 7)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let q = x / y\nassert_eq(out, q)",
        &inputs,
    );
}

#[test]
fn equiv_mux() {
    let inputs = make_inputs(&[("c", 1), ("a", 10), ("b", 20), ("out", 10)]);
    assert_witness_equivalence(
        &["out"],
        &["c", "a", "b"],
        "let r = if c { a } else { b }\nassert_eq(out, r)",
        &inputs,
    );
}

#[test]
fn equiv_poseidon() {
    let params = constraints::poseidon::PoseidonParams::bn254_t3();
    let hash = constraints::poseidon::poseidon_hash(&params, fe(1), fe(2));
    let inputs = make_inputs_fe(&[("l", fe(1)), ("r", fe(2)), ("h", hash)]);
    assert_witness_equivalence(
        &["h"],
        &["l", "r"],
        "let out = poseidon(l, r)\nassert_eq(h, out)",
        &inputs,
    );
}

#[test]
fn equiv_poseidon_chained() {
    let params = constraints::poseidon::PoseidonParams::bn254_t3();
    let h1 = constraints::poseidon::poseidon_hash(&params, fe(1), fe(2));
    let h2 = constraints::poseidon::poseidon_hash(&params, h1, fe(3));
    let inputs = make_inputs_fe(&[("a", fe(1)), ("b", fe(2)), ("c", fe(3)), ("out", h2)]);
    assert_witness_equivalence(
        &["out"],
        &["a", "b", "c"],
        "let h1 = poseidon(a, b)\nlet h2 = poseidon(h1, c)\nassert_eq(out, h2)",
        &inputs,
    );
}

#[test]
fn equiv_boolean_ops() {
    let inputs = make_inputs(&[("a", 1), ("b", 0), ("out", 1)]);
    assert_witness_equivalence(
        &["out"],
        &["a", "b"],
        "let r = a || b\nassert_eq(out, r)",
        &inputs,
    );
}

#[test]
fn equiv_comparison() {
    let inputs = make_inputs(&[("x", 3), ("y", 5), ("out", 1)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let r = x < y\nassert_eq(out, r)",
        &inputs,
    );
}

#[test]
fn equiv_for_loop() {
    // sum = 0 + 1 + 2 + 3 + 4 = 10
    let inputs = make_inputs(&[("out", 10)]);
    assert_witness_equivalence(
        &["out"],
        &[],
        "let acc = 0\nfor i in 0..5 {\n  let acc = acc + i\n}\nassert_eq(out, acc)",
        &inputs,
    );
}

#[test]
fn equiv_is_eq() {
    let inputs = make_inputs(&[("x", 5), ("y", 5), ("out", 1)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let r = x == y\nassert_eq(out, r)",
        &inputs,
    );
}

#[test]
fn equiv_is_neq() {
    let inputs = make_inputs(&[("x", 3), ("y", 5), ("out", 1)]);
    assert_witness_equivalence(
        &["out"],
        &["x", "y"],
        "let r = x != y\nassert_eq(out, r)",
        &inputs,
    );
}

// ============================================================================
// Early validation tests
// ============================================================================

#[test]
fn eval_catches_assertion_before_compile() {
    let source = "assert_eq(x, y)";
    let mut program = IrLowering::lower_circuit(source, &["x"], &["y"]).unwrap();
    ir::passes::optimize(&mut program);

    let inputs = make_inputs(&[("x", 1), ("y", 2)]);
    let mut compiler = R1CSCompiler::new();
    let err = compiler.compile_ir_with_witness(&program, &inputs);
    assert!(err.is_err(), "should fail with assertion error");
    let msg = format!("{}", err.unwrap_err());
    assert!(msg.contains("assert_eq failed"), "got: {msg}");
}

#[test]
fn eval_catches_div_zero_early() {
    let source = "let r = x / y\nassert_eq(out, r)";
    let mut program = IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);

    let inputs = make_inputs(&[("x", 1), ("y", 0), ("out", 0)]);
    let mut compiler = R1CSCompiler::new();
    let err = compiler.compile_ir_with_witness(&program, &inputs);
    assert!(err.is_err(), "should fail with division by zero");
    let msg = format!("{}", err.unwrap_err());
    assert!(msg.contains("division by zero"), "got: {msg}");
}

#[test]
fn eval_catches_missing_input_early() {
    let source = "assert_eq(x, y)";
    let mut program = IrLowering::lower_circuit(source, &["x"], &["y"]).unwrap();
    ir::passes::optimize(&mut program);

    let inputs = make_inputs(&[("x", 1)]); // missing "y"
    let mut compiler = R1CSCompiler::new();
    let err = compiler.compile_ir_with_witness(&program, &inputs);
    assert!(err.is_err(), "should fail with missing input");
    let msg = format!("{}", err.unwrap_err());
    assert!(msg.contains("missing input"), "got: {msg}");
}
