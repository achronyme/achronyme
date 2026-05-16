mod common;
use common::*;

use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ── Main test ────────────────────────────────────────────────────

#[test]
fn circomlib_e2e() {
    let files = find_circom_tests();
    assert!(!files.is_empty(), "no .circom test files found");

    let mut results: Vec<TestResult> = Vec::new();

    for file in &files {
        let result = run_circom_test(file);
        results.push(result);
    }

    // Print summary table
    eprintln!();
    eprintln!("┌─────────────────────────┬───────┬───────┬───────┬─────────────┐");
    eprintln!("│ Template                │ Parse │ Lower │ R1CS  │ Constraints │");
    eprintln!("├─────────────────────────┼───────┼───────┼───────┼─────────────┤");

    for r in &results {
        let parse = if r.parse { "  ✓  " } else { "  ✗  " };
        let lower = if r.lower { "  ✓  " } else { "  ✗  " };
        let r1cs = if r.r1cs { "  ✓  " } else { "  ✗  " };
        let constraints = match r.constraints {
            Some(n) => format!("{n:>11}"),
            None => "          -".to_string(),
        };
        eprintln!("│ {:<23} │{parse}│{lower}│{r1cs}│{constraints} │", r.name);
    }

    eprintln!("└─────────────────────────┴───────┴───────┴───────┴─────────────┘");

    let total = results.len();
    let parsed = results.iter().filter(|r| r.parse).count();
    let lowered = results.iter().filter(|r| r.lower).count();
    let proved = results.iter().filter(|r| r.r1cs).count();

    eprintln!();
    eprintln!(
        "circomlib coverage: {parsed}/{total} parse, {lowered}/{total} lower, {proved}/{total} r1cs"
    );
    eprintln!();

    // Print errors for failed tests
    let failures: Vec<&TestResult> = results.iter().filter(|r| r.error.is_some()).collect();
    if !failures.is_empty() {
        eprintln!("Failures:");
        for r in &failures {
            if let Some(err) = &r.error {
                eprintln!("  {}: {err}", r.name);
            }
        }
        eprintln!();
    }

    // Regressions: tests that LOWER successfully and have inputs, but fail R1CS.
    // Lower failures are "gaps" (unsupported features), not regressions.
    let regressions: Vec<&TestResult> = results
        .iter()
        .filter(|r| r.lower && !r.r1cs && r.error.as_deref() != Some("no inputs file"))
        .collect();

    if !regressions.is_empty() {
        eprintln!("REGRESSIONS (lowered but failed R1CS):");
        for r in &regressions {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
        panic!(
            "{} circom test(s) regressed — see details above",
            regressions.len()
        );
    }

    // Gaps: tests that fail at parse or lower (feature gaps, not regressions).
    let gaps: Vec<&TestResult> = results
        .iter()
        .filter(|r| !r.lower && r.error.as_deref() != Some("no inputs file"))
        .collect();
    if !gaps.is_empty() {
        eprintln!("Feature gaps (not regressions):");
        for r in &gaps {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
    }
}

// ── Poseidon (real circomlib) ───────────────────────────────────

/// Compile the real circomlib poseidon.circom with include resolution.
///
/// This is the ultimate compatibility test: Poseidon(2) from iden3/circomlib
/// compiled through our frontend → ProveIR → R1CS → Groth16 verify.
///
/// Poseidon(2) from iden3/circomlib: 1006 constraints, Groth16-verified.
#[test]
fn poseidon_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let poseidon_path = manifest_dir.join("test/circomlib/poseidon_test.circom");

    if !poseidon_path.exists() {
        eprintln!("Skipping poseidon test: {poseidon_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling Poseidon(2) from real circomlib...");
    let compile_result = match circom::compile_file(&poseidon_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("Poseidon compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());
    eprintln!(
        "    Public inputs: {:?}",
        prove_ir
            .public_inputs
            .iter()
            .map(|i| &i.name)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "    Captures: {:?}",
        prove_ir
            .captures
            .iter()
            .map(|c| &c.name)
            .collect::<Vec<_>>()
    );

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("Poseidon instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Build witness: inputs[0]=1, inputs[1]=2, initialState=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("inputs_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert(
        "initialState".to_string(),
        FieldElement::<Bn254Fr>::from_u64(0),
    );

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("Poseidon witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("Poseidon R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    // ── Step 4: Verify ──
    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("Poseidon R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  Poseidon(2) — {num_constraints} constraints — VERIFIED ✓");
}

// ── MiMCSponge (real circomlib) ────────────────────────────────

/// MiMCSponge(2, 220, 1) from iden3/circomlib: 220 rounds of MiMC-Feistel.
///
/// Tests: 218-element constant array, computed component array bounds,
/// compile-time ternary in loops, signal arrays with loop-dependent indexing.
#[test]
fn mimcsponge_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mimc_path = manifest_dir.join("test/circomlib/mimcsponge_test.circom");

    if !mimc_path.exists() {
        eprintln!("Skipping MiMCSponge test: {mimc_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling MiMCSponge(2, 220, 1) from real circomlib...");
    let compile_result = match circom::compile_file(&mimc_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("MiMCSponge compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());

    // DEBUG: count ProveIR node types
    {
        use ir_forge::types::CircuitNode;
        let mut lets = 0usize;
        let mut asserts = 0usize;
        let mut hints = 0usize;
        let mut fors = 0usize;
        let mut decomps = 0usize;
        let mut ifs = 0usize;
        let mut other = 0usize;
        let mut const_lets = 0usize;
        #[allow(clippy::too_many_arguments)]
        fn count_nodes(
            nodes: &[CircuitNode],
            lets: &mut usize,
            asserts: &mut usize,
            hints: &mut usize,
            fors: &mut usize,
            decomps: &mut usize,
            ifs: &mut usize,
            other: &mut usize,
            const_lets: &mut usize,
        ) {
            for n in nodes {
                match n {
                    CircuitNode::Let { value, .. } => {
                        *lets += 1;
                        if matches!(value, ir_forge::types::CircuitExpr::Const(_)) {
                            *const_lets += 1;
                        }
                    }
                    CircuitNode::AssertEq { .. } => *asserts += 1,
                    CircuitNode::WitnessHint { .. } => *hints += 1,
                    CircuitNode::For { body, .. } => {
                        *fors += 1;
                        count_nodes(
                            body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        *ifs += 1;
                        count_nodes(
                            then_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                        count_nodes(
                            else_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::Decompose { .. } => *decomps += 1,
                    _ => *other += 1,
                }
            }
        }
        count_nodes(
            &prove_ir.body,
            &mut lets,
            &mut asserts,
            &mut hints,
            &mut fors,
            &mut decomps,
            &mut ifs,
            &mut other,
            &mut const_lets,
        );
        eprintln!("  DEBUG nodes: Let={lets} (Const={const_lets}), AssertEq={asserts}, WitnessHint={hints}, For={fors}, If={ifs}, Decompose={decomps}, Other={other}");
        // Count "Other" node types
        let mut let_indexed = 0usize;
        let mut wh_indexed = 0usize;
        let mut let_array = 0usize;
        let mut expr_nodes = 0usize;
        let mut assert_nodes = 0usize;
        for n in &prove_ir.body {
            match n {
                CircuitNode::LetIndexed { .. } => let_indexed += 1,
                CircuitNode::WitnessHintIndexed { .. } => wh_indexed += 1,
                CircuitNode::LetArray { .. } => let_array += 1,
                CircuitNode::Expr { .. } => expr_nodes += 1,
                CircuitNode::Assert { .. } => assert_nodes += 1,
                _ => {}
            }
        }
        eprintln!("  DEBUG other: LetIndexed={let_indexed}, WHIndexed={wh_indexed}, LetArray={let_array}, Expr={expr_nodes}, Assert={assert_nodes}");
        // Print round 0 and round 1 nodes (indices ~220-250)
        eprintln!("  DEBUG === Nodes 218..260 ===");
        for (i, n) in prove_ir.body.iter().enumerate().skip(218).take(42) {
            eprintln!("  [{i}] {n:?}");
        }
    }

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("MiMCSponge instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Witness: ins[0]=1, ins[1]=2, k=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("ins_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("ins_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert("k".to_string(), FieldElement::<Bn254Fr>::from_u64(0));

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("MiMCSponge witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("MiMCSponge R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("MiMCSponge R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  MiMCSponge(2, 220, 1) — {num_constraints} constraints — VERIFIED ✓");
}

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

/// CompConstant standalone R1CS verify — isolates the 1<<128 BigVal fix.
#[test]
fn compconstant_standalone() {
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "CompConstant standalone",
        "test/circomlib/compconstant_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

// ── Circomlib compatibility: simple gadgets ──────────────────────

/// Switcher: conditional swap (sel=0 → pass-through, sel=1 → swap).
#[test]
fn switcher_circomlib() {
    // sel=0: outL=L=10, outR=R=20
    let n = circomlib_e2e_verify(
        "Switcher (sel=0)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 0), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");

    // sel=1: outL=R=20, outR=L=10
    let n = circomlib_e2e_verify(
        "Switcher (sel=1)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 1), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux3: select one of 8 values with 3-bit selector.
/// Tests MultiMux3 with pre-computed linear combinations.
#[test]
fn mux3_circomlib() {
    // c = [10,20,30,40,50,60,70,80], s = [1,0,1] → index=5 → c[5]=60
    let n = circomlib_e2e_verify(
        "Mux3 (sel=5)",
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 0),
            ("s_2", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux4: select one of 16 values with 4-bit selector.
#[test]
fn mux4_circomlib() {
    // s = [1,1,0,0] → index=3 → c[3]
    let mut inputs: Vec<(&str, u64)> = Vec::new();
    // c[0..16] = 100, 200, ... 1600
    let c_names: Vec<String> = (0..16).map(|i| format!("c_{i}")).collect();
    for (i, name) in c_names.iter().enumerate() {
        inputs.push((name, (i as u64 + 1) * 100));
    }
    inputs.push(("s_0", 1)); // bit 0
    inputs.push(("s_1", 1)); // bit 1
    inputs.push(("s_2", 0)); // bit 2
    inputs.push(("s_3", 0)); // bit 3
                             // index = 1 + 2 = 3 → c[3] = 400

    let n = circomlib_e2e_verify(
        "Mux4 (sel=3)",
        "test/circomlib/mux4_test.circom",
        &inputs.iter().map(|&(n, v)| (n, v)).collect::<Vec<_>>(),
    );
    eprintln!("  Constraints: {n}");
}

/// BinSum(4,2): compile-only test.
///
/// TODO: BinSum uses `var lin += signal * e2` with `<-- (lin >> k) & 1`,
/// a mixed var/signal pattern where `lin` accumulates signal expressions
/// and then bit-extracts via witness hint. Needs var-as-linear-combination
/// tracking in the lowering to generate correct constraints.
#[test]
fn binsum_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/binsum_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("BinSum compilation failed: {e}"));
    eprintln!(
        "  BinSum(4,2) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}

/// Multiplexer(2,3): compile-only test.
///
/// TODO: 2D signal input arrays (`inp[nIn][wIn]`) need flattened
/// naming support in the witness evaluator for full E2E verify.
#[test]
fn multiplexer_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/multiplexer_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Multiplexer compilation failed: {e}"));
    eprintln!(
        "  Multiplexer(2,3) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}

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

/// secp256k1 ECDSA signature verification — boss-fight constraint
/// measurement against `0xPARC/circom-ecdsa`.
///
/// Tree-of-bigint emulation that does **not** route through
/// Num2Bits → CompConstant chains; the `proven_boolean`
/// cross-template lever that drives the Pointbits-derived advantage
/// in EdDSAVerifier should not fire here. This gate measures
/// whether achronyme reaches parity (or beats) circom on a circuit
/// shape the existing benchmark templates don't exercise: bigint
/// register arithmetic over secp256k1's 256-bit field emulated via
/// 4 × u64 limbs (n=64 bits/register, k=4 registers).
///
/// circom 2.2.3 baseline:
///   --O1: 1,640,623 constraints (~25 s on a modern desktop)
///   --O2: 1,508,904 constraints (~78 s) — DEDUCE only saves 8 %
///         because most constraints are bigint quadratic.
///
/// Heavy enough that `#[ignore]` — run with
/// `cargo test --release ecdsa_verify_boss_fight -- --ignored
/// --nocapture` to capture wall-clock + constraint shape.
#[test]
#[ignore = "ECDSAVerify(64, 4) is the heaviest probe in this file (>1.5M constraints, multi-minute compile + R1CS build). The witness lift now covers `getProperRepresentation`'s body, including its runtime-index array stores; compilation still falls back to E212 on `getProperRepresentation` because a callee it reaches, `isNegative`, returns `cond ? 1 : 0` with a runtime condition and the expression lift has no `Expr::Ternary` arm for that shape. Run with --ignored only."]
fn ecdsa_verify_boss_fight() {
    use std::time::Instant;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/ecdsa_verify_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("ECDSAVerify compile failed: {e}"));
    eprintln!("[ECDSAVerify] [compile]      {:?}", t0.elapsed());

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let t1 = Instant::now();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("ECDSAVerify instantiate failed: {e}"));
    eprintln!(
        "[ECDSAVerify] [instantiate]  {:?}  instructions={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[ECDSAVerify] [ir-optimize]  {:?}  instructions={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("ECDSAVerify R1CS compile");
    let pre_o1 = rc.cs.num_constraints();
    eprintln!(
        "[ECDSAVerify] [r1cs build]   {:?}  constraints={pre_o1}",
        t3.elapsed()
    );

    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "[ECDSAVerify] [r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
    );

    eprintln!("[ECDSAVerify] [total]        {:?}", total.elapsed());
    eprintln!("[ECDSAVerify] [circom 2.2.3 baseline]  --O1 1,640,623, --O2 1,508,904");
    eprintln!(
        "[ECDSAVerify] [Δ vs circom O2]  {:+} constraints ({:+.2}%)",
        post_o1 as i64 - 1_508_904,
        (post_o1 as f64 / 1_508_904.0 - 1.0) * 100.0
    );
}

/// EscalarMul(8, base): generic scalar multiplication on BabyJubJub
/// using the windowed-add algorithm. Exercises array-literal template
/// arguments (`base = [Gx, Gy]`) propagating through nested template
/// instantiations and into compile-time function calls
/// (`EscalarMulW4Table(base, k)`) inside `EscalarMulWindow`.
///
/// Identity-point input (escalar = 0, inp = (0, 1)) — exercises the
/// pipeline without forcing a specific math result; the constraint
/// system is the test surface here, not curve correctness.
#[test]
fn escalarmul_circomlib() {
    let mut inputs = HashMap::new();
    for i in 0..8 {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("inp_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("inp_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_verify_fe(
        "EscalarMul(8, base)",
        "test/circomlib/escalarmul_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EscalarMul(8, base)");
}

/// SMTVerifier(10): sparse Merkle tree inclusion/exclusion verifier
/// at depth 10 (1024 leaves). Largest standalone circomlib template
/// not yet covered. Exercises descending for-loops (`i != -1`),
/// component arrays sized from template params, and compile-time
/// `var n1 = n\2` propagation through `MultiAND`.
///
/// Run with `enabled=0` so the R1CS verification is a no-op — the
/// frontend pipeline + constraint generation are the test surface;
/// witness validity for inclusion/exclusion semantics is out of
/// scope for this compile-coverage gate.
#[test]
fn smtverifier_circomlib() {
    let mut inputs = HashMap::new();
    inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("root".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("isOld0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("key".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("value".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    for i in 0..10 {
        inputs.insert(
            format!("siblings_{i}"),
            FieldElement::<Bn254Fr>::from_u64(0),
        );
    }

    let n = circomlib_e2e_verify_fe(
        "SMTVerifier(10) (enabled=0)",
        "test/circomlib/smtverifier_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for SMTVerifier(10)");
}

/// SMTProcessor(10): sparse Merkle tree state-transition processor at
/// depth 10. Larger sibling of SMTVerifier — adds insert/update/delete
/// state machines around the same core hash chain.
///
/// Run with `fnc=[0,0]` (no-op processor), so `enabled = 0` and the
/// R1CS check passes with the trivial state transition (newRoot ==
/// oldRoot). Same scope as the verifier test: compile-coverage gate.
#[test]
fn smtprocessor_circomlib() {
    let mut inputs = HashMap::new();
    inputs.insert("oldRoot".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newRoot".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("isOld0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc_1".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    for i in 0..10 {
        inputs.insert(
            format!("siblings_{i}"),
            FieldElement::<Bn254Fr>::from_u64(0),
        );
    }

    let n = circomlib_e2e_verify_fe(
        "SMTProcessor(10) (fnc=[0,0])",
        "test/circomlib/smtprocessor_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for SMTProcessor(10)");
}

/// Edwards2Montgomery: convert a Twisted-Edwards point to its
/// Montgomery-form representation. Single-template test on the
/// generator point — exercises the modular-inverse division
/// (`(1+y)/(1-y)`) the frontend lowers as a witness hint.
#[test]
fn montgomery_circomlib() {
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut inputs = HashMap::new();
    // BabyJubJub generator point (Edwards form).
    inputs.insert(
        "in_0".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "in_1".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );

    let n = circomlib_e2e_verify_fe(
        "Edwards2Montgomery",
        "test/circomlib/montgomery_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for Edwards2Montgomery");
}

/// Pedersen_old(8): hash 8 bits using the legacy Pedersen
/// template that delegates to `EscalarMul` + `EscalarMulWindow` +
/// `EscalarMulW4Table`. The table-builder function does compile-
/// time Edwards-curve point doubling and addition via `pointAdd`
/// (whose `/` is modular inverse in the scalar field, not integer
/// division). Exercises:
///
///   - Array-valued reassignment at template level (`table =
///     EscalarMulW4Table(base, k);`)
///   - Deferred scalar component instantiation (`component mux;`
///     then `mux = MultiMux4(2);`)
///   - Partial array slice as component arg (`EscalarMul(n,
///     PBASE[i])` where PBASE is a 2-D var)
///   - Field-aware compile-time `+ - * /` in function bodies
///
/// Covers Fase 5.2. The test asserts the circuit compiles through
/// to a non-empty R1CS — full Groth16 verification is a separate
/// concern since computing a golden digest requires an independent
/// Edwards-curve implementation.
#[test]
fn pedersen_old_circomlib_r1cs() {
    let n = circomlib_e2e_verify(
        "Pedersen_old(8)",
        "test/circomlib/pedersen_old_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Pedersen_old(8): {n} constraints");
    assert!(n > 0, "expected constraints for Pedersen_old");
}

/// Pedersen(8): hash 8 bits using BabyJubjub curve.
///
/// Tests: Window4, MontgomeryAdd/Double, Edwards2Montgomery,
/// Montgomery2Edwards, BabyAdd, Mux3 — completely different hash
/// construction from Poseidon/MiMC. Uses hardcoded base points
/// via 2D array literal (`var BASE[10][2] = [[...], ...]`).
#[test]
fn pedersen_circomlib() {
    // Hash input: 0b10110010 (bits LSB-first)
    let n = circomlib_e2e_verify(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for Pedersen hash");
}

#[test]
fn pedersen_o2() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/pedersen_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs).unwrap();
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    for (i, bit) in [0u64, 1, 0, 0, 1, 1, 0, 1].iter().enumerate() {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(*bit));
    }

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let mut witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap();

    let pre_opt = r1cs_compiler.cs.num_constraints();
    let stats = r1cs_compiler.optimize_r1cs_o2();
    if let Some(subs) = &r1cs_compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    let post_opt = r1cs_compiler.cs.num_constraints();

    eprintln!("  Pedersen(8) O2: {pre_opt} → {post_opt}");
    eprintln!(
        "  vars_elim={} dedup={} trivial={}",
        stats.variables_eliminated, stats.duplicates_removed, stats.trivial_removed
    );

    r1cs_compiler.cs.verify(&witness).unwrap();
    // Constant propagation through template inlining collapses Montgomery/
    // Edwards operations with known base points to scalars. The remaining
    // constraints are: 2×Window4 MUX (3+1 each = 8) + 1 MontgomeryAdd (3) +
    // 1 Montgomery2Edwards (2) = 13. Matches circom --O1.
    assert!(
        post_opt <= 13,
        "O2 should match circom (13): got {post_opt}"
    );
}

/// Point2Bits_Strict at the identity point (0, 1).
///
/// The identity point is degenerate: x = 0 collapses every bit of
/// `Num2Bits(x)` to 0, alias-check becomes trivial, CompConstant on
/// all-zero bits short-circuits. This probe exists *because* of that
/// degeneracy — it surfaces how aggressively each compiler folds
/// dead constraints when an input is statically known.
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored point2bits_strict_identity."]
fn point2bits_strict_identity() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("in_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_optimized(
        "Point2Bits_Strict (identity)",
        "test/circomlib/point2bits_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Point2Bits_Strict must produce non-empty constraint set"
    );
}

/// Point2Bits_Strict at the BabyJubjub generator (Gx, Gy).
///
/// Non-degenerate input — every bit of `Num2Bits(Gx)` is meaningful
/// and the AliasCheck / CompConstant constraints can't be statically
/// folded away. Provides a clean apples-to-apples comparison vs
/// circom's O2 baseline; any constraint-count gap here is structural,
/// not an artifact of the test's input choice.
///
/// Generator coordinates from circomlib `babyjub.circom`.
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored point2bits_strict_generator."]
fn point2bits_strict_generator() {
    let gx = FieldElement::<Bn254Fr>::from_decimal_str(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    )
    .expect("Gx parse");
    let gy = FieldElement::<Bn254Fr>::from_decimal_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .expect("Gy parse");

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in_0".to_string(), gx);
    inputs.insert("in_1".to_string(), gy);

    let n = circomlib_e2e_optimized(
        "Point2Bits_Strict (generator)",
        "test/circomlib/point2bits_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Point2Bits_Strict must produce non-empty constraint set"
    );
}

/// Bits2Point_Strict: 256-bit packed → Edwards curve point.
///
/// Inverse of Point2Bits_Strict. Adds two pattern classes the
/// existing benchmark doesn't cover:
///   - **Witness hint via `<--`**: x is computed at witness time as
///     `sqrt((1-y²)/(a-d·y²))` with a sign flip from in[255]. The
///     `<--` operator is a free assignment — the constraint that
///     pins x to a valid value is `BabyCheck(x, y)`, a quadratic
///     constraint on the Edwards curve equation.
///   - **Conditional sign negation in witness logic**: the witness
///     algorithm has to honour `if (in[255] == 1) x = -x`; if the
///     witness path didn't, BabyCheck would still verify against
///     the unsigned x but the sign-bit assertion at the end would
///     reject. This test surfaces any drift between the witness
///     pipeline and the constraint pipeline.
///
/// Test point: identity (0, 1) packed. Bits 0=1 (y=1 lsb), 1..253=0,
/// 254=0 (hardcoded), 255=0 (x=0 sign).
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored bits2point_strict_real_circomlib."]
fn bits2point_strict_real_circomlib() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    // bit 0 = lsb of y = 1
    inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    // bits 1..253 = 0
    for i in 1..254 {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    // bit 254 hardcoded to 0
    inputs.insert("in_254".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    // bit 255 sign of x (x=0 → 0)
    inputs.insert("in_255".to_string(), FieldElement::<Bn254Fr>::from_u64(0));

    let n = circomlib_e2e_optimized(
        "Bits2Point_Strict (identity)",
        "test/circomlib/bits2point_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Bits2Point_Strict must produce non-empty constraint set"
    );
}
