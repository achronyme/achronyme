//! Property-based tests for the IR → R1CS / Plonkish pipeline.
//!
//! These tests verify that for random field element inputs, the full
//! compilation pipeline (lower → compile → witness → verify) produces
//! valid proofs. This catches edge cases in constant folding, witness
//! generation, and bit decomposition that fixed example tests miss.

use std::collections::HashMap;

use ir::IrLowering;
use memory::FieldElement;
use proptest::prelude::*;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

// ============================================================================
// Helpers
// ============================================================================

/// Full R1CS pipeline: source → IR → optimize → R1CS → witness → verify.
fn r1cs_verify(public: &[(&str, FieldElement)], witness: &[(&str, FieldElement)], source: &str) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("R1CS verification failed");
}

/// Full Plonkish pipeline: source → IR → optimize → Plonkish → witness → verify.
fn plonkish_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("Plonkish witness gen failed");
    compiler
        .system
        .verify()
        .expect("Plonkish verification failed");
}

/// Both backends must accept the same circuit + inputs.
fn both_verify(public: &[(&str, FieldElement)], witness: &[(&str, FieldElement)], source: &str) {
    r1cs_verify(public, witness, source);
    plonkish_verify(public, witness, source);
}

/// Strategy: random u64 converted to FieldElement (stays small, avoids field wrapping).
fn fe_u64() -> impl Strategy<Value = FieldElement> {
    any::<u64>().prop_map(FieldElement::from_u64)
}

/// Strategy: small positive values (1..10000) for division denominators.
fn fe_nonzero() -> impl Strategy<Value = FieldElement> {
    (1u64..10_000).prop_map(FieldElement::from_u64)
}

/// Strategy: small values suitable for comparison (< 2^64, avoids field-edge issues).
fn fe_small() -> impl Strategy<Value = FieldElement> {
    (0u64..1_000_000).prop_map(FieldElement::from_u64)
}
/// R1CS pipeline WITHOUT optimization.
fn r1cs_verify_unoptimized(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    // NO optimization

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("unoptimized R1CS verification failed");
}

#[path = "proptest_circuit/adversarial.rs"]
mod adversarial;

#[path = "proptest_circuit/arithmetic.rs"]
mod arithmetic;

#[path = "proptest_circuit/comparison_cross_backend.rs"]
mod comparison_cross_backend;

#[path = "proptest_circuit/division_regressions.rs"]
mod division_regressions;

#[path = "proptest_circuit/optimization_soundness.rs"]
mod optimization_soundness;

#[path = "proptest_circuit/phase3_primitives.rs"]
mod phase3_primitives;
