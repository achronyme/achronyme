//! Solidity Verifier E2E Test
//!
//! Generates a Groth16 proof with Achronyme, creates a Solidity verifier contract,
//! and verifies the proof on-chain using Foundry (forge).
//!
//! Pipeline: Achronyme compile → Groth16 prove → generate verifier.sol →
//!           snarkjs soliditycalldata → forge test → verifyProof() returns true
//!
//! Gracefully skips if forge or snarkjs are not installed.

use std::collections::HashMap;
use std::process::Command;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use constraints::{write_r1cs, write_wtns};
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::field::PrimeId;
use memory::FieldElement;
use vm::ProveResult;

// ============================================================================
// Helpers
// ============================================================================

fn forge_available() -> bool {
    Command::new("forge")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn snarkjs_available() -> bool {
    Command::new("npx")
        .args(["snarkjs", "--version"])
        .output()
        .map(|o| o.status.success() || String::from_utf8_lossy(&o.stdout).contains("snarkjs"))
        .unwrap_or(false)
}

fn run_snarkjs(args: &[&str]) -> String {
    // args[0] = "snarkjs", rest are subcommand + flags
    // npx needs: npx snarkjs <subcommand> <args...>
    let output = Command::new("npx")
        .args(args) // pass all: ["snarkjs", "powersoftau", "new", ...]
        .output()
        .expect("npx snarkjs failed");
    assert!(
        output.status.success(),
        "snarkjs failed: {}\nstderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

/// Compile circuit, generate R1CS + witness, and return compiler + witness.
fn compile_circuit(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let mut program = IrLowering::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();

    let witness_vec = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness_vec)
        .expect("R1CS verification failed");

    (compiler, witness_vec)
}

// ============================================================================
// E2E Test
// ============================================================================

/// Full E2E: Achronyme compile → Groth16 prove → verifier.sol → snarkjs calldata → forge test
#[test]
fn solidity_e2e_mul() {
    if !forge_available() {
        eprintln!("SKIP: forge not available");
        return;
    }
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== SOLIDITY E2E: Multiplication 6 × 7 = 42 ===");

    // 1. Compile circuit
    let (compiler, witness) = compile_circuit(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    eprintln!(
        "  Step 1/6: Circuit compiled ({} constraints)",
        compiler.cs.num_constraints()
    );

    // 2. Export .r1cs + .wtns
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let r1cs_path = d.join("circuit.r1cs");
    let wtns_path = d.join("witness.wtns");
    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();
    eprintln!("  Step 2/6: R1CS + WTNS exported");

    // 3. snarkjs trusted setup + prove
    let pot = d.join("pot.ptau");
    let pot1 = d.join("pot1.ptau");
    let pot_final = d.join("pot_final.ptau");
    let zkey0 = d.join("circuit_0000.zkey");
    let zkey1 = d.join("circuit_0001.zkey");

    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "new",
        "bn128",
        "12",
        pot.to_str().unwrap(),
        "-v",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "contribute",
        pot.to_str().unwrap(),
        pot1.to_str().unwrap(),
        "--name=test",
        "-v",
        "-e=random",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "prepare",
        "phase2",
        pot1.to_str().unwrap(),
        pot_final.to_str().unwrap(),
        "-v",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "groth16",
        "setup",
        r1cs_path.to_str().unwrap(),
        pot_final.to_str().unwrap(),
        zkey0.to_str().unwrap(),
    ]);
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "contribute",
        zkey0.to_str().unwrap(),
        zkey1.to_str().unwrap(),
        "--name=test",
        "-v",
        "-e=random",
    ]);
    eprintln!("  Step 3/6: Trusted setup complete");

    // 4. Generate proof with snarkjs
    let proof_json_path = d.join("proof.json");
    let public_json_path = d.join("public.json");
    run_snarkjs(&[
        "snarkjs",
        "groth16",
        "prove",
        zkey1.to_str().unwrap(),
        wtns_path.to_str().unwrap(),
        proof_json_path.to_str().unwrap(),
        public_json_path.to_str().unwrap(),
    ]);
    eprintln!("  Step 4/6: Groth16 proof generated");

    // 5. Generate Solidity verifier + calldata with snarkjs
    let verifier_path = d.join("Groth16Verifier.sol");
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "solidityverifier",
        zkey1.to_str().unwrap(),
        verifier_path.to_str().unwrap(),
    ]);

    let calldata_output = run_snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "soliditycalldata",
        public_json_path.to_str().unwrap(),
        proof_json_path.to_str().unwrap(),
    ]);
    eprintln!("  Step 5/6: Verifier.sol + calldata generated");

    // snarkjs soliditycalldata outputs: ["0x..","0x.."],[[...],[...]],["0x..","0x.."],["0x.."]
    // We need to parse it and generate proper Solidity code with typed variables
    let calldata_raw = calldata_output.trim().replace('"', "");

    // Parse the 4 groups: pA, pB, pC, pubSignals
    // Format: [a0,a1],[[b00,b01],[b10,b11]],[c0,c1],[pub0,pub1,...]
    // We'll use a simpler approach: pass calldata inline but cast pubSignals
    // The issue is small hex values (like 0x2a for 42) get typed as uint8
    // Solution: use Solidity `abi.decode` or assign to typed variables

    // 6. Create Foundry project and run test
    let forge_dir = d.join("foundry_test");
    std::fs::create_dir_all(forge_dir.join("src")).unwrap();
    std::fs::create_dir_all(forge_dir.join("test")).unwrap();

    std::fs::write(
        forge_dir.join("foundry.toml"),
        "[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = [\"lib\"]\n",
    )
    .unwrap();

    // Copy verifier
    std::fs::copy(
        &verifier_path,
        forge_dir.join("src").join("Groth16Verifier.sol"),
    )
    .unwrap();

    // Parse calldata groups by splitting on top-level commas between ] and [
    // Simpler: use snarkjs to get proof.json and format ourselves
    let proof_content = std::fs::read_to_string(&proof_json_path).unwrap();
    let public_content = std::fs::read_to_string(&public_json_path).unwrap();
    let proof_val: serde_json::Value = serde_json::from_str(&proof_content).unwrap();
    let public_val: Vec<String> = serde_json::from_str(&public_content).unwrap();

    let pi_a = &proof_val["pi_a"];
    let pi_b = &proof_val["pi_b"];
    let pi_c = &proof_val["pi_c"];

    // Build typed Solidity test
    let pub_signals_decl = public_val
        .iter()
        .enumerate()
        .map(|(i, v)| format!("        pubSignals[{i}] = {v};"))
        .collect::<Vec<_>>()
        .join("\n");

    let num_pub = public_val.len();

    let test_sol = format!(
        r#"// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../src/Groth16Verifier.sol";

contract VerifierTest {{
    Groth16Verifier verifier;

    function setUp() public {{
        verifier = new Groth16Verifier();
    }}

    function testValidProof() public view {{
        uint[2] memory pA = [
            uint256({a0}),
            uint256({a1})
        ];
        uint[2][2] memory pB = [
            [uint256({b00}), uint256({b01})],
            [uint256({b10}), uint256({b11})]
        ];
        uint[2] memory pC = [
            uint256({c0}),
            uint256({c1})
        ];
        uint[{num_pub}] memory pubSignals;
{pub_signals}

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        require(result, "Valid proof must verify on EVM");
    }}
}}
"#,
        a0 = pi_a[0].as_str().unwrap(),
        a1 = pi_a[1].as_str().unwrap(),
        // G2 swap: snarkjs proof.json stores (c0, c1), EIP-197 expects (c1, c0)
        b00 = pi_b[0][1].as_str().unwrap(), // x.c1 (imag first)
        b01 = pi_b[0][0].as_str().unwrap(), // x.c0 (real second)
        b10 = pi_b[1][1].as_str().unwrap(), // y.c1 (imag first)
        b11 = pi_b[1][0].as_str().unwrap(), // y.c0 (real second)
        c0 = pi_c[0].as_str().unwrap(),
        c1 = pi_c[1].as_str().unwrap(),
        num_pub = num_pub,
        pub_signals = pub_signals_decl,
    );

    std::fs::write(forge_dir.join("test").join("Verifier.t.sol"), &test_sol).unwrap();

    // Run forge test
    let output = Command::new("forge")
        .args(["test", "-vvv"])
        .current_dir(&forge_dir)
        .output()
        .expect("forge failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        eprintln!("  Step 6/6: forge test PASSED ✓");
        eprintln!(
            "\n  ★ Achronyme R1CS + witness → snarkjs proof → Solidity verifier → EVM verification"
        );
        eprintln!("    Full pipeline confirmed: proof verifies on-chain.");
    } else {
        eprintln!("  forge stdout: {stdout}");
        eprintln!("  forge stderr: {stderr}");
        panic!("forge test FAILED — Solidity verifier rejected the proof");
    }
}

/// Same test but with Poseidon — the most complex circuit.
#[test]
fn solidity_e2e_poseidon() {
    if !forge_available() {
        eprintln!("SKIP: forge not available");
        return;
    }
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== SOLIDITY E2E: Poseidon(1, 2) — on-chain verification ===");

    let expected = FieldElement::from_decimal_str(
        "7853200120776062878684798364095072458815029376092732009249414926327459813530",
    )
    .unwrap();

    let (compiler, witness) = compile_circuit(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", expected), ("a", fe(1)), ("b", fe(2))],
    );
    eprintln!("  Constraints: {}", compiler.cs.num_constraints());

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let r1cs_path = d.join("circuit.r1cs");
    let wtns_path = d.join("witness.wtns");
    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();

    // Setup
    let pot = d.join("pot.ptau");
    let pot1 = d.join("pot1.ptau");
    let pot_final = d.join("pot_final.ptau");
    let zkey0 = d.join("circuit_0000.zkey");
    let zkey1 = d.join("circuit_0001.zkey");

    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "new",
        "bn128",
        "12",
        pot.to_str().unwrap(),
        "-v",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "contribute",
        pot.to_str().unwrap(),
        pot1.to_str().unwrap(),
        "--name=test",
        "-v",
        "-e=random",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "powersoftau",
        "prepare",
        "phase2",
        pot1.to_str().unwrap(),
        pot_final.to_str().unwrap(),
        "-v",
    ]);
    run_snarkjs(&[
        "snarkjs",
        "groth16",
        "setup",
        r1cs_path.to_str().unwrap(),
        pot_final.to_str().unwrap(),
        zkey0.to_str().unwrap(),
    ]);
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "contribute",
        zkey0.to_str().unwrap(),
        zkey1.to_str().unwrap(),
        "--name=test",
        "-v",
        "-e=random",
    ]);

    // Prove
    let proof_path = d.join("proof.json");
    let public_path = d.join("public.json");
    run_snarkjs(&[
        "snarkjs",
        "groth16",
        "prove",
        zkey1.to_str().unwrap(),
        wtns_path.to_str().unwrap(),
        proof_path.to_str().unwrap(),
        public_path.to_str().unwrap(),
    ]);

    // Verifier + calldata
    let verifier_path = d.join("Groth16Verifier.sol");
    run_snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "solidityverifier",
        zkey1.to_str().unwrap(),
        verifier_path.to_str().unwrap(),
    ]);
    let calldata = run_snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "soliditycalldata",
        public_path.to_str().unwrap(),
        proof_path.to_str().unwrap(),
    ]);

    // Forge test
    let forge_dir = d.join("foundry_test");
    std::fs::create_dir_all(forge_dir.join("src")).unwrap();
    std::fs::create_dir_all(forge_dir.join("test")).unwrap();
    std::fs::write(
        forge_dir.join("foundry.toml"),
        "[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = [\"lib\"]\n",
    )
    .unwrap();
    std::fs::copy(
        &verifier_path,
        forge_dir.join("src").join("Groth16Verifier.sol"),
    )
    .unwrap();

    let proof_content = std::fs::read_to_string(&proof_path).unwrap();
    let public_content = std::fs::read_to_string(&public_path).unwrap();
    let proof_val: serde_json::Value = serde_json::from_str(&proof_content).unwrap();
    let public_val: Vec<String> = serde_json::from_str(&public_content).unwrap();

    let pi_a = &proof_val["pi_a"];
    let pi_b = &proof_val["pi_b"];
    let pi_c = &proof_val["pi_c"];
    let num_pub = public_val.len();

    let pub_signals_decl = public_val
        .iter()
        .enumerate()
        .map(|(i, v)| format!("        pubSignals[{i}] = {v};"))
        .collect::<Vec<_>>()
        .join("\n");

    let test_sol = format!(
        r#"// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../src/Groth16Verifier.sol";

contract VerifierTest {{
    Groth16Verifier verifier;

    function setUp() public {{
        verifier = new Groth16Verifier();
    }}

    function testPoseidonProof() public view {{
        uint[2] memory pA = [
            uint256({a0}),
            uint256({a1})
        ];
        uint[2][2] memory pB = [
            [uint256({b00}), uint256({b01})],
            [uint256({b10}), uint256({b11})]
        ];
        uint[2] memory pC = [
            uint256({c0}),
            uint256({c1})
        ];
        uint[{num_pub}] memory pubSignals;
{pub_signals}

        bool result = verifier.verifyProof(pA, pB, pC, pubSignals);
        require(result, "Poseidon proof must verify on EVM");
    }}
}}
"#,
        a0 = pi_a[0].as_str().unwrap(),
        a1 = pi_a[1].as_str().unwrap(),
        // G2 swap: snarkjs proof.json (c0, c1) → EIP-197 (c1, c0)
        b00 = pi_b[0][1].as_str().unwrap(),
        b01 = pi_b[0][0].as_str().unwrap(),
        b10 = pi_b[1][1].as_str().unwrap(),
        b11 = pi_b[1][0].as_str().unwrap(),
        c0 = pi_c[0].as_str().unwrap(),
        c1 = pi_c[1].as_str().unwrap(),
        num_pub = num_pub,
        pub_signals = pub_signals_decl,
    );

    std::fs::write(forge_dir.join("test").join("Verifier.t.sol"), &test_sol).unwrap();

    let output = Command::new("forge")
        .args(["test", "-vvv"])
        .current_dir(&forge_dir)
        .output()
        .expect("forge failed");

    if output.status.success() {
        eprintln!("  forge test: PASSED ✓");
        eprintln!("  ★ Poseidon(1,2) ZK proof verified on EVM — complete production pipeline");
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("  forge stdout: {stdout}");
        eprintln!("  forge stderr: {stderr}");
        panic!("Poseidon Solidity E2E FAILED");
    }
}
