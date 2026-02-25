//! End-to-end proof generation tests.
//!
//! These tests exercise the full pipeline: source → IR → compile → witness → proof → verify
//! for both Groth16 (ark-groth16) and Plonkish (halo2 KZG) backends.

use std::collections::HashMap;

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
use memory::FieldElement;
use vm::ProveResult;

fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}

/// Lower self-contained source → optimize → bool_prop → R1CS compile with witness.
/// Returns the compiler (with constraint system) and the witness vector.
fn lower_and_compile_r1cs(
    source: &str,
    inputs: &[(&str, u64)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let input_map: HashMap<String, FieldElement> = inputs
        .iter()
        .map(|(k, v)| (k.to_string(), fe(*v)))
        .collect();
    lower_and_compile_r1cs_fe(source, input_map)
}

/// Same as `lower_and_compile_r1cs` but accepts FieldElement inputs directly.
fn lower_and_compile_r1cs_fe(
    source: &str,
    input_map: HashMap<String, FieldElement>,
) -> (R1CSCompiler, Vec<FieldElement>) {
    let (_, _, mut program) =
        ir::IrLowering::lower_self_contained(source).expect("lower_self_contained failed");
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("compile_ir_with_witness failed");

    // Sanity: verify constraints before handing off to proof gen
    compiler
        .cs
        .verify(&witness)
        .expect("R1CS constraint verification failed");

    (compiler, witness)
}

/// Lower self-contained source → optimize → bool_prop → Plonkish compile with witness.
/// Returns the compiler ready for proof generation.
fn lower_and_compile_plonkish(source: &str, inputs: &[(&str, u64)]) -> PlonkishCompiler {
    let (_, _, mut program) =
        ir::IrLowering::lower_self_contained(source).expect("lower_self_contained failed");
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let input_map: HashMap<String, FieldElement> = inputs
        .iter()
        .map(|(k, v)| (k.to_string(), fe(*v)))
        .collect();

    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("plonkish compile_ir_with_witness failed");

    // Sanity: verify Plonkish constraints
    compiler
        .system
        .verify()
        .expect("Plonkish constraint verification failed");

    compiler
}

// ============================================================================
// Groth16 tests
// ============================================================================

#[test]
fn e2e_groth16_simple_multiply() {
    let source = r#"
witness a
witness b
public c
assert_eq(a * b, c)
"#;
    let (compiler, witness) = lower_and_compile_r1cs(source, &[("a", 6), ("b", 7), ("c", 42)]);

    let cache_dir = tempfile::tempdir().unwrap();
    let result = cli::groth16::generate_proof(&compiler.cs, &witness, cache_dir.path())
        .expect("generate_proof failed");

    match result {
        ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let proof: serde_json::Value =
                serde_json::from_str(&proof_json).expect("proof_json is not valid JSON");
            assert_eq!(proof["protocol"], "groth16");
            assert_eq!(proof["curve"], "bn128");
            assert!(proof["pi_a"].is_array(), "missing pi_a");
            assert!(proof["pi_b"].is_array(), "missing pi_b");
            assert!(proof["pi_c"].is_array(), "missing pi_c");

            let public: Vec<String> =
                serde_json::from_str(&public_json).expect("public_json is not valid JSON");
            assert_eq!(public.len(), 1, "expected 1 public input");
            assert_eq!(public[0], "42", "public input should be 42");

            let vkey: serde_json::Value =
                serde_json::from_str(&vkey_json).expect("vkey_json is not valid JSON");
            assert_eq!(vkey["protocol"], "groth16");
            assert_eq!(vkey["curve"], "bn128");
            assert_eq!(vkey["nPublic"], 1);
            assert!(vkey["vk_alpha_1"].is_array(), "missing vk_alpha_1");
            assert!(vkey["IC"].is_array(), "missing IC");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof, got VerifiedOnly"),
    }
}

#[test]
fn e2e_groth16_poseidon_hash() {
    let source = r#"
witness a
witness b
public h
assert_eq(poseidon(a, b), h)
"#;
    // Compute poseidon(1, 2) offline to use as public input h
    let params = constraints::poseidon::PoseidonParams::bn254_t3();
    let hash = constraints::poseidon::poseidon_hash(&params, fe(1), fe(2));

    let mut input_map = HashMap::new();
    input_map.insert("a".to_string(), fe(1));
    input_map.insert("b".to_string(), fe(2));
    input_map.insert("h".to_string(), hash);

    let (compiler, witness) = lower_and_compile_r1cs_fe(source, input_map);

    // Should have 361+ constraints from Poseidon
    assert!(
        compiler.cs.num_constraints() >= 361,
        "expected >= 361 constraints for poseidon, got {}",
        compiler.cs.num_constraints()
    );

    let cache_dir = tempfile::tempdir().unwrap();
    let result = cli::groth16::generate_proof(&compiler.cs, &witness, cache_dir.path())
        .expect("generate_proof failed");

    match result {
        ProveResult::Proof {
            proof_json,
            public_json,
            ..
        } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "groth16");

            let public: Vec<String> = serde_json::from_str(&public_json).unwrap();
            assert_eq!(public.len(), 1);
            assert_eq!(public[0], hash.to_decimal_string());
        }
        ProveResult::VerifiedOnly => panic!("expected Proof"),
    }
}

#[test]
fn e2e_groth16_boolean_logic() {
    // Circuit using range_check, assert, and mux — exercises bool_prop path
    let source = r#"
witness flag
witness a
witness b
public r
range_check(flag, 1)
assert_eq(mux(flag, a, b), r)
"#;
    // flag=1 → selects a=10 → r=10
    let (compiler, witness) =
        lower_and_compile_r1cs(source, &[("flag", 1), ("a", 10), ("b", 20), ("r", 10)]);

    let cache_dir = tempfile::tempdir().unwrap();
    let result = cli::groth16::generate_proof(&compiler.cs, &witness, cache_dir.path())
        .expect("generate_proof failed");

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "groth16");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof"),
    }
}

#[test]
fn e2e_groth16_wrong_witness_fails() {
    let source = r#"
witness a
witness b
public c
assert_eq(a * b, c)
"#;
    // a=6, b=7 but c=99 (should be 42)
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("lower failed");
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut input_map = HashMap::new();
    input_map.insert("a".to_string(), fe(6));
    input_map.insert("b".to_string(), fe(7));
    input_map.insert("c".to_string(), fe(99));

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    // Should fail at IR evaluation (assert_eq mismatch) or constraint verification
    let result = compiler.compile_ir_with_witness(&program, &input_map);
    assert!(result.is_err(), "expected error for wrong witness, got Ok");
}

// ============================================================================
// Plonkish / KZG tests
// ============================================================================

#[test]
fn e2e_plonkish_simple_multiply() {
    let source = r#"
witness a
witness b
public c
assert_eq(a * b, c)
"#;
    let compiler = lower_and_compile_plonkish(source, &[("a", 6), ("b", 7), ("c", 42)]);

    let cache_dir = tempfile::tempdir().unwrap();
    let result = cli::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("generate_plonkish_proof failed");

    match result {
        ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let proof: serde_json::Value =
                serde_json::from_str(&proof_json).expect("proof_json is not valid JSON");
            assert_eq!(proof["protocol"], "plonk");
            assert_eq!(proof["curve"], "bn128");
            assert!(proof["proof"].is_string(), "missing proof hex");
            assert!(proof["k"].is_number(), "missing k");

            let public: Vec<String> =
                serde_json::from_str(&public_json).expect("public_json is not valid JSON");
            assert_eq!(public.len(), 1);
            assert_eq!(public[0], "42");

            let vkey: serde_json::Value =
                serde_json::from_str(&vkey_json).expect("vkey_json is not valid JSON");
            assert_eq!(vkey["protocol"], "plonk");
            assert_eq!(vkey["curve"], "bn128");
            assert!(vkey["vkey"].is_string(), "missing vkey hex");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof, got VerifiedOnly"),
    }
}

#[test]
fn e2e_plonkish_add_sub() {
    // Exercises add/sub/mul through the Plonkish deferred arithmetic path
    let source = r#"
witness a
witness b
public s
public d
assert_eq(a + b, s)
assert_eq(a - b, d)
"#;
    let compiler = lower_and_compile_plonkish(source, &[("a", 10), ("b", 3), ("s", 13), ("d", 7)]);

    let cache_dir = tempfile::tempdir().unwrap();
    let result = cli::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("generate_plonkish_proof failed");

    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof"),
    }
}

#[test]
fn e2e_plonkish_wrong_witness_fails() {
    let source = r#"
witness a
witness b
public c
assert_eq(a * b, c)
"#;
    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("lower failed");
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut input_map = HashMap::new();
    input_map.insert("a".to_string(), fe(6));
    input_map.insert("b".to_string(), fe(7));
    input_map.insert("c".to_string(), fe(99));

    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    let result = compiler.compile_ir_with_witness(&program, &input_map);
    assert!(result.is_err(), "expected error for wrong witness, got Ok");
}

// ============================================================================
// Cache reuse test
// ============================================================================

#[test]
fn e2e_groth16_cache_reuse() {
    let source = r#"
witness a
witness b
public c
assert_eq(a * b, c)
"#;
    let cache_dir = tempfile::tempdir().unwrap();

    // First run: a=3, b=5, c=15
    let (compiler1, witness1) = lower_and_compile_r1cs(source, &[("a", 3), ("b", 5), ("c", 15)]);
    let result1 = cli::groth16::generate_proof(&compiler1.cs, &witness1, cache_dir.path())
        .expect("first generate_proof failed");
    assert!(matches!(result1, ProveResult::Proof { .. }));

    // Cache directory should now contain key files
    let entries: Vec<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !entries.is_empty(),
        "cache dir should contain cached keys after first run"
    );
    let cache_subdir = entries[0].path();
    assert!(
        cache_subdir.join("proving_key.bin").exists(),
        "proving_key.bin should be cached"
    );
    assert!(
        cache_subdir.join("verifying_key.bin").exists(),
        "verifying_key.bin should be cached"
    );

    // Second run: same circuit structure, different witness (a=2, b=9, c=18)
    let (compiler2, witness2) = lower_and_compile_r1cs(source, &[("a", 2), ("b", 9), ("c", 18)]);
    let result2 = cli::groth16::generate_proof(&compiler2.cs, &witness2, cache_dir.path())
        .expect("second generate_proof failed (should use cache)");

    match result2 {
        ProveResult::Proof { public_json, .. } => {
            let public: Vec<String> = serde_json::from_str(&public_json).unwrap();
            assert_eq!(public[0], "18", "second proof should have c=18");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof"),
    }

    // Cache dir should still have exactly one subdirectory (same circuit → same key)
    let entries_after: Vec<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries_after.len(),
        1,
        "same circuit should reuse same cache entry"
    );
}
