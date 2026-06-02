use super::*;

// ── Circomlib compatibility: crypto primitives ───────────────────

/// AliasCheck: verifies 254-bit input is not an alias (< field modulus).
/// Uses CompConstant(-1). Input: 42 in binary (254 bits).
#[test]
fn aliascheck_circomlib() {
    // 42 = 0b101010, pad to 254 bits
    let bits_42: u64 = 42;
    let mut inputs = Vec::new();
    let names: Vec<String> = (0..254).map(|i| format!("in_{i}")).collect();
    for (i, name) in names.iter().enumerate() {
        let bit = if i < 64 { (bits_42 >> i) & 1 } else { 0 };
        inputs.push((name.as_str(), bit));
    }
    let n = circomlib_e2e_verify(
        "AliasCheck (42)",
        "test/circomlib/aliascheck_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

/// Sign: determine sign of a 254-bit field element.
/// Returns 0 for "positive" (< (p-1)/2), 1 for "negative".
#[test]
fn sign_circomlib() {
    // Small value (42): sign should be 0
    let bits: u64 = 42;
    let mut inputs = Vec::new();
    let names: Vec<String> = (0..254).map(|i| format!("in_{i}")).collect();
    for (i, name) in names.iter().enumerate() {
        let bit = if i < 64 { (bits >> i) & 1 } else { 0 };
        inputs.push((name.as_str(), bit));
    }
    let n = circomlib_e2e_verify(
        "Sign (42, positive)",
        "test/circomlib/sign_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

/// EdDSAMiMCVerifier: BabyJubjub EdDSA signature verifier using MiMC7
/// as the hash function. Covers the combination of every feature
/// Fase 5 opened:
///   - MultiMiMC7(5, 91) compile-time round constants
///   - CompConstant(2736...) with `1 << 128` seed (BigVal)
///   - BabyDbl + BabyAdd Edwards-curve component composition
///   - EscalarMul with compile-time Pedersen-style base points
///   - `pointAdd` field-aware division at compile time
///
/// Runs with `enabled=0` so the signature validity assertion is
/// short-circuited — all other inputs still need to be valid
/// curve points / field elements so `Num2Bits` and the doubling
/// chain don't fail. Reuses the same Base8 coordinates as the
/// EdDSAPoseidon test since both verifiers share the BabyJubjub
/// curve.
///
/// Closes Fase 5.3.
#[test]
fn eddsamimc_r1cs() {
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
        "EdDSAMiMC R1CS (enabled=0)",
        "test/circomlib/eddsamimc_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EdDSAMiMC verifier");
}

/// EdDSAMiMCSponge: same wiring as EdDSAMiMC but the message hash is
/// MiMCSponge instead of MiMC. Sibling template — verifies the
/// frontend handles the alternative hash through the same component
/// composition pipeline.
#[test]
fn eddsamimcsponge_r1cs() {
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
        "EdDSAMiMCSponge R1CS (enabled=0)",
        "test/circomlib/eddsamimcsponge_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EdDSAMiMCSponge verifier");
}

/// BinSub(8): subtract two 8-bit binary inputs with borrow output.
/// Exercises the `2**i` runtime-exponent rewrite (loop variable as
/// exponent → left-shift) used throughout circomlib bit arithmetic.
#[test]
fn binsub_circomlib() {
    // 5 - 3 = 2; LSB-first bit decomposition. The 2D `in[2][8]` array
    // flattens to in_0..in_7 (operand 0) + in_8..in_15 (operand 1).
    let n = circomlib_e2e_verify(
        "BinSub(8)",
        "test/circomlib/binsub_test.circom",
        &[
            ("in_0", 1),
            ("in_1", 0),
            ("in_2", 1),
            ("in_3", 0),
            ("in_4", 0),
            ("in_5", 0),
            ("in_6", 0),
            ("in_7", 0),
            ("in_8", 1),
            ("in_9", 1),
            ("in_10", 0),
            ("in_11", 0),
            ("in_12", 0),
            ("in_13", 0),
            ("in_14", 0),
            ("in_15", 0),
        ],
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for BinSub(8)");
}

/// Bits2Point_Strict: 256-bit packed BabyJubjub point unpacker with
/// alias check + sign-bit reconstruction. Compile + instantiate only —
/// witness inputs require a valid packed point (254-bit y, 1-bit zero
/// padding, 1-bit sign), and `out[0] <-- sqrt(...)` is filled by the
/// Artik witness lift, so a bare `circomlib_e2e_verify_fe` call would
/// need cross-field square-root setup that isn't worth the test
/// complexity for a compile-time gate.
#[test]
fn bits2point_strict_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/pointbits_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib/circuits")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Bits2Point_Strict compilation failed: {e}"));

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("Bits2Point_Strict instantiation failed: {e}"));
    ir::passes::optimize(&mut program);

    eprintln!(
        "  Bits2Point_Strict — {} nodes → {} instructions — INSTANTIATED ✓",
        result.prove_ir.body.len(),
        program.len()
    );
}

/// EdDSAVerifier(1): the original EdDSA scheme using Pedersen-hash for
/// the message and BabyJubjub for the curve. Wires sub-component
/// inputs via the `==>` reverse-assignment shape:
///
///   for (i=0; i<254; i++) { S[i] ==> compConstant.in[i]; }
///   for (i=0; i<256; i++) { bits2pointA.in[i] <== A[i]; }
///
/// The first form pins the Class B classifier's reverse-assign
/// branch — pre-fix this template failed at instantiation with
/// `symbolic indexed write into compConstant.in but the array is
/// not declared in this scope`. Compile + instantiate + R1CS-build
/// is the test surface; full witness verification requires valid
/// Pedersen-hash signature data which is out of scope for a compile-
/// time gate.
///
/// Constraint-count baseline (circom 2.2.3, `eddsa_test.circom`):
/// `--O1` = 16,498 (16,003 non-linear + 495 linear), `--O2` = 7,417
/// (all non-linear). Achronyme's post-O1 number is the comparison
/// surface; the template uses `Bits2Point_Strict` and
/// `Point2Bits_Strict` heavily and should inherit the
/// cross-template `proven_boolean` advantage measured in
/// `point2bits_strict_*` / `bits2point_strict_*`.
#[test]
fn eddsa_verifier_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsa_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib/circuits")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("EdDSAVerifier compilation failed: {e}"));

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("EdDSAVerifier instantiation failed: {e}"));
    ir::passes::optimize(&mut program);

    eprintln!(
        "  EdDSAVerifier(1) — {} nodes → {} instructions — INSTANTIATED ✓",
        result.prove_ir.body.len(),
        program.len()
    );

    // Build R1CS (witness-less — this gate measures constraint shape,
    // not signature validity). Apply O1, then compare to circom O2.
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("EdDSAVerifier R1CS compile");
    let pre_o1 = rc.cs.num_constraints();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "  EdDSAVerifier(1) R1CS: pre-O1 {pre_o1} → post-O1 {post_o1} \
         (vars eliminated: {}, rounds: {})",
        stats.variables_eliminated, stats.rounds
    );
    eprintln!("  circom 2.2.3 baseline: --O1 16,498, --O2 7,417");
    eprintln!(
        "  Δ vs circom O2: {} constraints ({:+.2}%)",
        post_o1 as i64 - 7_417,
        (post_o1 as f64 / 7_417.0 - 1.0) * 100.0
    );
}

/// Lysis register-frame ceiling regression.
///
/// `Secp256k1AddUnequal(64, 4)` lifts the circomlib bigint helper
/// `secp256k1_addunequal_func`, whose `var sum[2][100]` return
/// flattens to a single `WitnessCall` with 200 outputs. The lysis
/// walker frame is a `u8` ceiling (255 slots); a `WitnessCall` on the
/// classic register-output path needs one frame register per output
/// and is atomic (the split machinery chains templates between
/// instructions, never within one), so a 200-output inline call
/// entered from an already-populated frame cannot be split and
/// overflows. Nesting the helper in an outer fixed-bound loop
/// reproduces that populated-frame context minimally. The walker must
/// route a wide-output `WitnessCall` to the heap-output path whenever
/// its outputs would not fit the current frame; this circuit must
/// instantiate through lysis without a frame overflow. Cheap
/// (sub-second) — not `#[ignore]`.
#[test]
fn secp256k1_addunequal_loop_nested_lysis_frame_fit() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/secp256k1_addunequal_loop_nested_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Secp256k1AddUnequalLoopNested compilation failed: {e}"));

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let program = result
        .prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| {
            panic!("Secp256k1AddUnequalLoopNested lysis instantiation failed: {e}")
        });

    assert!(
        !program.is_empty(),
        "lysis program must be non-empty after instantiation"
    );
    eprintln!(
        "  Secp256k1AddUnequalLoopNested — {} nodes → {} instructions — INSTANTIATED ✓",
        result.prove_ir.body.len(),
        program.len()
    );
}
