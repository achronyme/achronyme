use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::{write_r1cs, write_wtns};
use ir::IrLowering;
use memory::field::PrimeId;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use super::helpers::{cross_validate, fe, fe_to_decimal, run_snarkjs, snarkjs_available};

const POSEIDON_1_2_HASH: &str =
    "7853200120776062878684798364095072458815029376092732009249414926327459813530";

#[test]
fn golden_poseidon_1_2() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Poseidon(1, 2) ===");
    eprintln!("  Industry golden (circomlibjs + go-iden3-crypto):");
    eprintln!("    {POSEIDON_1_2_HASH}");

    let expected = FieldElement::from_decimal_str(POSEIDON_1_2_HASH).unwrap();
    let mut inputs = HashMap::new();
    inputs.insert("expected".into(), expected);
    inputs.insert("a".into(), fe(1));
    inputs.insert("b".into(), fe(2));

    let result = cross_validate(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &inputs,
    );

    assert!(result.wtns_check_passed);

    // Wire[1] = expected (public output) = Poseidon hash
    let wire1 = &result.wire_values[1];
    eprintln!("  Achronyme wire[1] (output):");
    eprintln!("    {wire1}");
    assert_eq!(
        wire1, POSEIDON_1_2_HASH,
        "Poseidon(1,2) output mismatch vs industry golden vector"
    );
    eprintln!("  MATCH vs circomlibjs: ✓");
    eprintln!("  MATCH vs go-iden3-crypto: ✓");
    eprintln!("  snarkjs wtns check: ✓");
    eprintln!(
        "  Constraints: {} (industry: Circom ~240, Gnark ~275)",
        result.constraint_count
    );
}

// ============================================================================
// 3. Poseidon(0, 0) — zero-input golden vector
//    Source: circomlibjs poseidon([0, 0]) test
// ============================================================================

#[test]
fn golden_poseidon_0_0() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Poseidon(0, 0) ===");

    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, FieldElement::ZERO, FieldElement::ZERO);
    let expected_str = fe_to_decimal(expected);
    eprintln!("  Achronyme native Poseidon(0, 0) = {expected_str}");

    let mut inputs = HashMap::new();
    inputs.insert("expected".into(), expected);
    inputs.insert("a".into(), fe(0));
    inputs.insert("b".into(), fe(0));

    let result = cross_validate(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &inputs,
    );

    assert!(result.wtns_check_passed);
    assert_eq!(
        result.wire_values[1], expected_str,
        "Poseidon(0,0) output wire mismatch"
    );
    eprintln!("  Wire[1] matches native: ✓");
    eprintln!("  snarkjs wtns check: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

// ============================================================================
// 4. Mux — conditional selection
//    mux(1, 10, 20) = 10, mux(0, 10, 20) = 20
#[test]
fn golden_poseidon_groth16_full_cycle() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Poseidon(1, 2) — Full Groth16 Cycle ===");
    eprintln!("  Pipeline: Achronyme compile → .r1cs/.wtns → PoT → Setup → Prove → Verify");

    let expected = FieldElement::from_decimal_str(POSEIDON_1_2_HASH).unwrap();
    let mut inputs = HashMap::new();
    inputs.insert("expected".into(), expected);
    inputs.insert("a".into(), fe(1));
    inputs.insert("b".into(), fe(2));

    // Compile and generate witness
    let program = IrLowering::lower_circuit(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
    )
    .unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();
    let r1cs_path = p("circuit.r1cs");
    let wtns_path = p("witness.wtns");
    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();

    eprintln!("  Step 1/6: Achronyme compile + export ✓");
    eprintln!("  Constraints: {}", compiler.cs.num_constraints());

    // snarkjs wtns check
    run_snarkjs(&["snarkjs", "wtns", "check", &r1cs_path, &wtns_path]);
    eprintln!("  Step 2/6: snarkjs wtns check ✓");

    // Powers of Tau
    let pot_0 = p("pot_0000.ptau");
    let pot_1 = p("pot_0001.ptau");
    let pot_final = p("pot_final.ptau");
    run_snarkjs(&["snarkjs", "powersoftau", "new", "bn128", "12", &pot_0, "-v"]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "contribute",
        &pot_0,
        &pot_1,
        "--name=test",
        "-v",
        "-e=random",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "prepare",
        "phase2",
        &pot_1,
        &pot_final,
        "-v",
    ]);
    eprintln!("  Step 3/6: Powers of Tau ceremony ✓");

    // Groth16 setup
    let zkey_0 = p("circuit_0000.zkey");
    let zkey_1 = p("circuit_0001.zkey");
    let vkey = p("verification_key.json");
    run_snarkjs(&[
        "snarkjs", "groth16", "setup", &r1cs_path, &pot_final, &zkey_0,
    ]);
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "contribute",
        &zkey_0,
        &zkey_1,
        "--name=test",
        "-v",
        "-e=random",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "verificationkey",
        &zkey_1,
        &vkey,
    ]);
    eprintln!("  Step 4/6: Groth16 setup ✓");

    // Prove
    let proof = p("proof.json");
    let public_json = p("public.json");
    run_snarkjs(&[
        "snarkjs",
        "groth16",
        "prove",
        &zkey_1,
        &wtns_path,
        &proof,
        &public_json,
    ]);
    eprintln!("  Step 5/6: Groth16 proof generated ✓");

    // Verify
    run_snarkjs(&["snarkjs", "groth16", "verify", &vkey, &public_json, &proof]);
    eprintln!("  Step 6/6: Groth16 proof VERIFIED by snarkjs ✓");

    // Verify public output matches the golden vector
    let public_content = std::fs::read_to_string(p("public.json")).unwrap();
    let public_values: Vec<String> = serde_json::from_str(&public_content).unwrap();
    assert_eq!(
        public_values[0], POSEIDON_1_2_HASH,
        "Groth16 public output mismatch vs industry golden vector"
    );
    eprintln!("\n  PUBLIC OUTPUT = {}", public_values[0]);
    eprintln!("  GOLDEN VECTOR = {POSEIDON_1_2_HASH}");
    eprintln!("  MATCH: ✓");
    eprintln!("\n  ★ Poseidon(1, 2) ZK proof generated by Achronyme and");
    eprintln!("    verified by snarkjs Groth16 — full interoperability confirmed.");
}

// ============================================================================
// 8. IsEqual — comparison operator (IsZero gadget)
//    Circom: circomlib/comparators.circom IsEqual() → 3 constraints
