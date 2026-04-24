//! Plonkish Cross-Validation — Level 2: Full halo2 KZG prove/verify cycle
//!
//! Generates real KZG-PlonK proofs using halo2 and verifies them.
//! This is the Plonkish equivalent of the Groth16 full cycle test.
//!
//! Note: range_check circuits are excluded because halo2 PSE fork
//! doesn't support simple selectors in lookup arguments during proof generation.

use std::collections::HashMap;

use akron::ProveResult;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
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

fn lower_and_compile(source: &str, input_pairs: &[(&str, u64)]) -> PlonkishCompiler {
    // Parse inputs: first token after "public" → public, after "witness" → witness
    let pub_names: Vec<&str> = source
        .lines()
        .filter(|l| l.starts_with("public "))
        .map(|l| l.trim_start_matches("public ").trim())
        .collect();
    let wit_names: Vec<&str> = source
        .lines()
        .filter(|l| l.starts_with("witness "))
        .map(|l| l.trim_start_matches("witness ").trim())
        .collect();

    // Strip declarations for lower_circuit
    let body: String = source
        .lines()
        .filter(|l| !l.starts_with("public ") && !l.starts_with("witness "))
        .collect::<Vec<_>>()
        .join("\n");

    let mut program = IrLowering::lower_circuit(&body, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir(&program)
        .expect("Plonkish compilation failed");

    let mut inputs: HashMap<String, FieldElement> = HashMap::new();
    for (name, val) in input_pairs {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler
        .system
        .verify()
        .expect("Plonkish verification failed");

    compiler
}

fn lower_and_compile_fe(source: &str, input_pairs: &[(&str, FieldElement)]) -> PlonkishCompiler {
    let pub_names: Vec<&str> = source
        .lines()
        .filter(|l| l.starts_with("public "))
        .map(|l| l.trim_start_matches("public ").trim())
        .collect();
    let wit_names: Vec<&str> = source
        .lines()
        .filter(|l| l.starts_with("witness "))
        .map(|l| l.trim_start_matches("witness ").trim())
        .collect();

    let body: String = source
        .lines()
        .filter(|l| !l.starts_with("public ") && !l.starts_with("witness "))
        .collect::<Vec<_>>()
        .join("\n");

    let mut program = IrLowering::lower_circuit(&body, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir(&program)
        .expect("Plonkish compilation failed");

    let inputs: HashMap<String, FieldElement> = input_pairs
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler
        .system
        .verify()
        .expect("Plonkish verification failed");

    compiler
}

fn prove_and_verify(compiler: PlonkishCompiler) -> ProveResult {
    let cache_dir = tempfile::tempdir().unwrap();
    proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("halo2 proof generation failed")
}

// ============================================================================
// Level 2: Full halo2 KZG prove/verify cycle
// ============================================================================

#[test]
fn halo2_prove_verify_mul() {
    let source = "public out\nwitness a\nwitness b\nassert_eq(a * b, out)";
    let compiler = lower_and_compile(source, &[("out", 42), ("a", 6), ("b", 7)]);
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof {
            proof_json,
            public_json,
            ..
        } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");

            // public_json is a plain array: ["42"]
            let public: Vec<String> = serde_json::from_str(&public_json).unwrap();
            assert!(
                public.iter().any(|v| v == "42"),
                "public output should contain 42, got: {public:?}"
            );
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_div() {
    let source = "public out\nwitness a\nwitness b\nassert_eq(a / b, out)";
    let compiler = lower_and_compile(source, &[("out", 6), ("a", 42), ("b", 7)]);
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_mux() {
    let source = "public out\nwitness c\nwitness a\nwitness b\nassert_eq(mux(c, a, b), out)";
    let compiler = lower_and_compile(source, &[("out", 10), ("c", 1), ("a", 10), ("b", 20)]);
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_poseidon() {
    let expected =
        fe_str("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    let source =
        "public expected\nwitness a\nwitness b\nlet h = poseidon(a, b)\nassert_eq(h, expected)";
    let compiler = lower_and_compile_fe(
        source,
        &[("expected", expected), ("a", fe(1)), ("b", fe(2))],
    );
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof {
            public_json,
            proof_json,
            ..
        } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");

            // Verify public output matches Poseidon golden vector
            // public_json is a plain array: ["7853200..."]
            let public: Vec<String> = serde_json::from_str(&public_json).unwrap();
            let golden =
                "7853200120776062878684798364095072458815029376092732009249414926327459813530";
            assert!(
                public.iter().any(|v| v == golden),
                "halo2 public output must match Poseidon golden vector from circomlibjs"
            );
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_iseq() {
    let source = "public out\nwitness a\nwitness b\nassert_eq(a == b, out)";
    let compiler = lower_and_compile(source, &[("out", 1), ("a", 5), ("b", 5)]);
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_bool_logic() {
    let source = "public out\nwitness a\nwitness b\nassert_eq(a && b, out)";
    let compiler = lower_and_compile(source, &[("out", 1), ("a", 1), ("b", 1)]);
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        _ => panic!("expected Proof variant"),
    }
}

#[test]
fn halo2_prove_verify_complex_circuit() {
    let source =
        "public out\nwitness a\nwitness b\nwitness c\nwitness d\nassert_eq((a + b) * c - d, out)";
    let compiler = lower_and_compile(
        source,
        &[("out", 15), ("a", 2), ("b", 3), ("c", 4), ("d", 5)],
    );
    let result = prove_and_verify(compiler);

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        _ => panic!("expected Proof variant"),
    }
}
