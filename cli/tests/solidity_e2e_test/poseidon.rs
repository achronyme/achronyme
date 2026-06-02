use super::*;

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
    let _calldata = run_snarkjs(&[
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
        r#"// SPDX-License-Identifier: Apache-2.0
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
