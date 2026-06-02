use super::*;

// ── BabyJubjub (real circomlib) ────────────────────────────────

/// BabyAdd + BabyDbl + BabyCheck from iden3/circomlib.
///
/// Tests: Edwards curve point addition with witness hints (division),
/// reverse constraint assign (`==>`), `===` constraints with var
/// coefficients, and component composition (BabyDbl wraps BabyAdd).
#[test]
fn babyjub_real_circomlib() {
    // Generator point G = (Gx, Gy) of BabyJubjub
    // We use the base point from circomlib:
    // Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553
    // Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203
    // These are large field elements — for witness hints with division,
    // we need the actual field values. Use small test points instead:
    // The identity point (0, 1) is always on the curve.
    // BabyAdd(0, 1, 0, 1) should give BabyDbl(0, 1) = (0, 1) (identity doubled).
    let n = circomlib_e2e_verify(
        "BabyJub (Add+Dbl+Check)",
        "test/circomlib/babyjub_test.circom",
        &[("x1", 0), ("y1", 1), ("x2", 0), ("y2", 1)],
    );
    assert!(n > 0, "expected at least 1 constraint");
}

// ── EscalarMulFix (real circomlib) ─────────────────────────────

/// EscalarMulFix(3, BASE8): scalar multiplication on BabyJubjub.
///
/// Tests: WindowMulFix (MultiMux3 + MontgomeryDouble/Add),
/// SegmentMulFix orchestration, Edwards↔Montgomery conversion,
/// component arrays, 2D signal wiring.
#[test]
fn escalarmulfix_real_circomlib() {
    // 3-bit scalar = 5 (bits: 1,0,1)
    let n = circomlib_e2e_verify(
        "EscalarMulFix(3, BASE8)",
        "test/circomlib/escalarmulfix_test.circom",
        &[("e_0", 1), ("e_1", 0), ("e_2", 1)],
    );
    eprintln!("  Constraints: {n}");
}

/// EscalarMulAny(254): full R1CS verify with identity point.
///
/// Uses n=254 (real-world EdDSA scalar size). Official circom produces
/// 2,312 constraints for this circuit (2,310 non-linear + 2 linear).
#[test]
fn escalarmulany_r1cs() {
    let mut inputs = HashMap::new();
    // 254 bits of scalar, all zero
    for i in 0..254 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    // Identity point (0, 1) — zeropoint guard forces G8
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_verify_fe(
        "EscalarMulAny(254) R1CS",
        "test/circomlib/escalarmulany254_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    eprintln!("  Official circom: 2312 constraints");
    assert!(n > 2000, "expected >2000 constraints, got {n}");
}

/// EscalarMulAny(149): multi-segment chaining variant. With n=149 the
/// segment count is `(149-1)\148 + 1 = 2`, so this exercises the
/// segment-stitching path that the n=254 fast path collapses into a
/// single segment of 148 + 1 leftover bits. Identity point + zero
/// scalar (zeropoint guard maps to G8 internally).
#[test]
fn escalarmulany_149_r1cs() {
    let mut inputs = HashMap::new();
    for i in 0..149 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_verify_fe(
        "EscalarMulAny(149) R1CS",
        "test/circomlib/escalarmulany_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EscalarMulAny(149)");
}

/// EscalarMulAny(254): full Groth16 proof generation and verification.
#[test]
fn escalarmulany_groth16() {
    let mut inputs = HashMap::new();
    for i in 0..254 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/escalarmulany254_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("instantiation failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap_or_else(|e| panic!("witness failed: {e}"));
    for (k, v) in &fe_captures {
        all_signals.entry(k.clone()).or_insert(*v);
    }

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS failed: {e}"));

    r1cs.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));

    let n = r1cs.cs.num_constraints();
    eprintln!("  ✓ R1CS: {n} constraints");

    // Groth16 proof
    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof generation failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            eprintln!("  ✓ Groth16 proof generated ({} bytes)", proof_json.len());

            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verification failed: {e}"));

            assert!(valid, "Groth16 proof did not verify!");
            eprintln!("  ✓ Groth16 proof VERIFIED!");
            eprintln!("\n  EscalarMulAny(149) — {n} constraints — GROTH16 VERIFIED ✓");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// EdDSAPoseidon: the "boss final" — full signature verification.
/// Depends on: Num2Bits(253), CompConstant, Poseidon(5), Num2Bits_strict,
/// BabyDbl, IsZero, EscalarMulAny(254), BabyAdd, EscalarMulFix(253),
/// ForceEqualIfEnabled.
#[test]
fn eddsaposeidon_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsaposeidon_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    eprintln!("Compiling EdDSAPoseidonVerifier...");
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    eprintln!(
        "  ✓ Compiled: {} body nodes, {} public, {} witness",
        prove_ir.body.len(),
        prove_ir.public_inputs.len(),
        prove_ir.witness_inputs.len(),
    );

    // Instantiate to verify the node ordering is correct
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    eprintln!(
        "\n  EdDSAPoseidonVerifier — {} nodes → {} instructions — INSTANTIATED ✓",
        prove_ir.body.len(),
        program.len()
    );
}

/// EdDSaPoseidon R1CS verification with enabled=0.
///
/// With enabled=0, ForceEqualIfEnabled doesn't check the signature,
/// so any input values satisfy the constraints. This validates that
/// the entire constraint system is well-formed and satisfiable.
///
/// Depends on the BigVal 256-bit evaluator: CompConstant's
/// `var b = (1 << 128) - 1` evaluates correctly under it.
#[test]
fn eddsaposeidon_r1cs() {
    // BabyJubjub base point (Base8) — a valid curve point.
    // Even with enabled=0, intermediate values must be valid for Num2Bits.
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut inputs = HashMap::new();
    inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    // R8 = same base point (arbitrary valid point for enabled=0)
    inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "EdDSAPoseidon R1CS (enabled=0)",
        "test/circomlib/eddsaposeidon_test.circom",
        &inputs,
    );
    eprintln!("  Constraints (pre-opt): {n}");

    // Also test with R1CS linear constraint optimization
    let n_opt = circomlib_e2e_optimized(
        "EdDSAPoseidon R1CS optimized",
        "test/circomlib/eddsaposeidon_test.circom",
        &inputs,
    );
    eprintln!("  Constraints (post-opt): {n_opt}");
    eprintln!("  circom 2.2.3 --O0: 21254, --O1: 8086, --O2: 4217");
    eprintln!(
        "  Ratio vs circom O2 baseline: {:.3}x",
        n_opt as f64 / 4217.0
    );
}
