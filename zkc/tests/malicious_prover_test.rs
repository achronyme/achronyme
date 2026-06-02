//! Systematic Malicious Prover Tests
//!
//! These tests simulate an adversarial prover who KNOWS the circuit structure
//! and attempts to forge witnesses that satisfy the constraints while producing
//! incorrect outputs.
//!
//! Unlike proptest (random valid/invalid inputs) and cargo-fuzz (random bytes),
//! these tests directly manipulate the witness vector post-generation to simulate
//! specific attack vectors documented in the ZK vulnerability literature.
//!
//! Attack taxonomy:
//!   A1. Bit flip — corrupt a single wire value
//!   A2. Zero witness — set all intermediate wires to zero
//!   A3. Field boundary — inject p-1 values
//!   A4. Output forgery — change the public output wire
//!   A5. Poseidon state corruption — tamper with hash intermediate wires
//!   A6. Mux condition bypass — non-boolean condition values
//!   A7. Division inverse forgery — wrong modular inverse
//!   A8. Bit decomposition overflow — Dark Forest class attack
//!
//! Reference: 0xPARC zk-bug-tracker, circomspect analysis

#![allow(clippy::needless_range_loop, clippy::manual_swap, unused_mut)]

use std::collections::HashMap;

use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn p_minus_1() -> FieldElement {
    FieldElement::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap()
}

/// Compile a circuit and generate a VALID witness, returning the compiler
/// and witness vector for subsequent manipulation.
fn compile_valid_witness(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let w = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("valid witness gen failed");

    // Sanity: valid witness must pass
    compiler.cs.verify(&w).expect("valid witness must verify");
    (compiler, w)
}

// ============================================================================
// A1. Bit flip attack — corrupt a single wire value
// ============================================================================

#[test]
fn a1_bit_flip_on_mul_output() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Flip the output wire (wire 1)
    w[1] = fe(43);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A1: flipped output must be rejected"
    );
}

#[test]
fn a1_bit_flip_on_intermediate_wire() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b + c, out)",
        &["out"],
        &["a", "b", "c"],
        &[("out", fe(47)), ("a", fe(6)), ("b", fe(7)), ("c", fe(5))],
    );
    // Wire 0 = ONE, wire 1 = out, wires 2-4 = a,b,c, wire 5+ = intermediates
    // Corrupt an intermediate (the mul result)
    if w.len() > 5 {
        w[5] = w[5].add(&fe(1)); // off by one
        assert!(
            compiler.cs.verify(&w).is_err(),
            "A1: flipped intermediate must be rejected"
        );
    }
}

#[test]
fn a1_bit_flip_every_wire() {
    let (compiler, w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Flip each wire individually — all must fail (except if the flip is a no-op)
    for i in 0..w.len() {
        let mut corrupted = w.clone();
        corrupted[i] = corrupted[i].add(&fe(1));
        // wire 0 is ONE — corrupting it definitely fails
        // Other wires should also fail
        let result = compiler.cs.verify(&corrupted);
        assert!(
            result.is_err(),
            "A1: flipping wire {i} should be rejected (value was {:?})",
            w[i].to_canonical()
        );
    }
}

// ============================================================================
// A2. Zero witness attack — set all intermediates to zero
// ============================================================================

#[test]
fn a2_zero_all_intermediates_mul() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Zero out all intermediate wires (keep ONE, public, witness)
    let n_fixed = 1 + compiler.cs.num_pub_inputs() + 2; // ONE + pub + witnesses
    for i in n_fixed..w.len() {
        w[i] = FieldElement::ZERO;
    }
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A2: zeroed intermediates must be rejected"
    );
}

#[test]
fn a2_zero_all_intermediates_poseidon() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    let n_fixed = 1 + 1 + 2; // ONE + expected + a,b
    for i in n_fixed..w.len() {
        w[i] = FieldElement::ZERO;
    }
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A2: zeroed Poseidon intermediates must be rejected"
    );
}

// ============================================================================
// A3. Field boundary injection — inject p-1 into wires
// ============================================================================

#[test]
fn a3_pminus1_as_output() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a + b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(13)), ("a", fe(6)), ("b", fe(7))],
    );
    w[1] = p_minus_1(); // forge output as p-1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A3: p-1 as output must be rejected when real output is 13"
    );
}

#[test]
fn a3_pminus1_as_witness_input() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    w[2] = p_minus_1(); // forge witness a as p-1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A3: p-1 as witness input must be rejected"
    );
}

// ============================================================================
// A4. Output forgery — change the public output to a desired value
// ============================================================================

#[test]
fn a4_forge_output_to_one() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    w[1] = fe(1); // attacker wants output to be 1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A4: forged output = 1 must be rejected"
    );
}

#[test]
fn a4_forge_poseidon_output() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    // Try to forge: claim poseidon(1,2) = 0
    w[1] = FieldElement::ZERO;
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A4: forged Poseidon output must be rejected"
    );
}

#[path = "malicious_prover_test/advanced_attacks.rs"]
mod advanced_attacks;
