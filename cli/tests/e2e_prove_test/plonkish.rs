use super::*;

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
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
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
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
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

#[test]
fn e2e_plonkish_poseidon_hash() {
    let source = r#"
witness a
witness b
public h
assert_eq(poseidon(a, b), h)
"#;
    let params = constraints::poseidon::PoseidonParams::bn254_t3();
    let hash = constraints::poseidon::poseidon_hash(&params, fe(1), fe(2));

    let mut input_map = HashMap::new();
    input_map.insert("a".to_string(), fe(1));
    input_map.insert("b".to_string(), fe(2));
    input_map.insert("h".to_string(), hash);

    let (_, _, mut program) = ir::IrLowering::lower_self_contained(source).expect("lower failed");
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("plonkish compile_ir_with_witness failed");
    compiler
        .system
        .verify()
        .expect("Plonkish constraint verification failed");

    let cache_dir = tempfile::tempdir().unwrap();
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("generate_plonkish_proof failed");

    match result {
        ProveResult::Proof {
            proof_json,
            public_json,
            ..
        } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");

            let public: Vec<String> = serde_json::from_str(&public_json).unwrap();
            assert_eq!(public.len(), 1);
            assert_eq!(public[0], hash.to_decimal_string());
        }
        ProveResult::VerifiedOnly => panic!("expected Proof"),
    }
}

#[test]
fn e2e_plonkish_boolean_logic() {
    // Uses mux (boolean enforcement) and if/else — exercises bool_prop path.
    // NOTE (resolved in beta.9): range_check now works with halo2 PSE
    // via lookup_any + fixed columns (no dynamic selector compression).
    let source = r#"
witness flag
witness a
witness b
public r
assert_eq(mux(flag, a, b), r)
"#;
    // flag=1 → selects a=10 → r=10
    let compiler =
        lower_and_compile_plonkish(source, &[("flag", 1), ("a", 10), ("b", 20), ("r", 10)]);

    let cache_dir = tempfile::tempdir().unwrap();
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
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
fn e2e_plonkish_range_check() {
    // Previously excluded — range_check now works with lookup_any + fixed columns.
    let source = r#"
witness x
range_check(x, 8)
public out
assert_eq(x, out)
"#;
    let compiler = lower_and_compile_plonkish(source, &[("x", 42), ("out", 42)]);
    let cache_dir = tempfile::tempdir().unwrap();
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("range_check KZG proof generation failed");
    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof with range_check"),
    }
}

#[test]
fn e2e_plonkish_islt_bounded() {
    // IsLtBounded depends on range_check — validates the full D7 optimization with KZG.
    let source = r#"
witness a
witness b
range_check(a, 8)
range_check(b, 8)
public out
assert_eq(a < b, out)
"#;
    let compiler = lower_and_compile_plonkish(source, &[("a", 3), ("b", 5), ("out", 1)]);
    let cache_dir = tempfile::tempdir().unwrap();
    let result = proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir.path())
        .expect("IsLtBounded KZG proof generation failed");
    match result {
        ProveResult::Proof { proof_json, .. } => {
            let proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(proof["protocol"], "plonk");
        }
        ProveResult::VerifiedOnly => panic!("expected Proof with IsLtBounded"),
    }
}
