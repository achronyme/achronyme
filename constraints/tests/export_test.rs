use constraints::r1cs::{ConstraintSystem, LinearCombination};
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::FieldElement;
use std::process::Command;

/// Build a*b=c circuit (1 public output, 2 witnesses, 1 constraint).
fn make_mul_circuit() -> (ConstraintSystem, Vec<FieldElement>) {
    let mut cs = ConstraintSystem::new();
    let c = cs.alloc_input();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    cs.enforce(
        LinearCombination::from_variable(a),
        LinearCombination::from_variable(b),
        LinearCombination::from_variable(c),
    );
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(42),
        FieldElement::from_u64(6),
        FieldElement::from_u64(7),
    ];
    assert!(cs.verify(&witness).is_ok());
    (cs, witness)
}

#[test]
fn test_r1cs_roundtrip_structure() {
    let (cs, _) = make_mul_circuit();
    let data = write_r1cs(&cs, PrimeId::Bn254);

    // Magic + version
    assert_eq!(&data[0..4], b"r1cs");
    assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);

    // 3 sections
    assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 3);

    // Header section body is 64 bytes
    let sec1_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
    assert_eq!(sec1_size, 64);
}

#[test]
fn test_wtns_roundtrip_structure() {
    let (_, witness) = make_mul_circuit();
    let data = write_wtns(&witness, PrimeId::Bn254);

    assert_eq!(&data[0..4], b"wtns");
    assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 2);

    // Values section size = 4 * 32 = 128
    // Section 2 header: after file header (12) + sec1 header (12) + sec1 body (40) = 64
    let sec2_offset = 12 + 12 + 40;
    let sec2_size = u64::from_le_bytes(data[sec2_offset + 4..sec2_offset + 12].try_into().unwrap());
    assert_eq!(sec2_size, 128);
}

#[test]
fn test_r1cs_and_wtns_consistent_wire_count() {
    let (cs, witness) = make_mul_circuit();
    let r1cs_data = write_r1cs(&cs, PrimeId::Bn254);
    let wtns_data = write_wtns(&witness, PrimeId::Bn254);

    // nWires from r1cs header (offset 24 + 36 = 60)
    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());

    // nWitness from wtns header (offset 24 + 36 = 60)
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());

    assert_eq!(n_wires, n_witness);
    assert_eq!(n_wires, 4);
}

/// Integration test: compile through the full pipeline and verify export.
#[test]
fn test_e2e_pipeline_export() {
    use compiler::r1cs_backend::R1CSCompiler;
    use compiler::witness_gen::WitnessGenerator;
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program: ir::types::IrProgram =
        IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let r1cs_data = write_r1cs(&compiler.cs, PrimeId::Bn254);
    assert_eq!(&r1cs_data[0..4], b"r1cs");

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    let wtns_data = write_wtns(&witness, PrimeId::Bn254);
    assert_eq!(&wtns_data[0..4], b"wtns");
}

/// Check if snarkjs is available (skip tests gracefully if not installed).
fn snarkjs_available() -> bool {
    // Try direct `snarkjs` first (global install), fall back to `npx snarkjs`
    Command::new("snarkjs")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("npx")
            .args(["snarkjs", "--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Resolve whether to run snarkjs directly or via npx.
fn snarkjs_cmd() -> (&'static str, bool) {
    if Command::new("snarkjs")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        ("snarkjs", true) // direct: args start at index 1 (skip "snarkjs")
    } else {
        ("npx", false) // npx: pass all args including "snarkjs"
    }
}

/// Run a snarkjs command. Args should start with "snarkjs" (e.g. &["snarkjs", "groth16", ...]).
fn snarkjs(args: &[&str]) {
    let (cmd, direct) = snarkjs_cmd();
    let effective_args = if direct { &args[1..] } else { args };
    let output = Command::new(cmd)
        .args(effective_args)
        .output()
        .unwrap_or_else(|e| panic!("{cmd} not available: {e}"));
    assert!(
        output.status.success(),
        "command failed: {cmd} {}\nstdout: {}\nstderr: {}",
        effective_args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Full Groth16 integration test: powers of tau → setup → prove → verify.
/// Requires node.js and snarkjs (npx snarkjs).
#[test]
fn test_snarkjs_groth16_full() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }

    use compiler::r1cs_backend::R1CSCompiler;
    use compiler::witness_gen::WitnessGenerator;
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program: ir::types::IrProgram =
        IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = |name: &str| d.join(name).to_str().unwrap().to_string();

    let r1cs_path = p("circuit.r1cs");
    let wtns_path = p("witness.wtns");

    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();

    // Powers of Tau ceremony
    let pot12 = p("pot12_0000.ptau");
    let pot12_1 = p("pot12_0001.ptau");
    let pot12_final = p("pot12_final.ptau");
    snarkjs(&["snarkjs", "powersoftau", "new", "bn128", "12", &pot12, "-v"]);
    snarkjs(&[
        "snarkjs",
        "powersoftau",
        "contribute",
        &pot12,
        &pot12_1,
        "--name=test",
        "-v",
        "-e=random",
    ]);
    snarkjs(&[
        "snarkjs",
        "powersoftau",
        "prepare",
        "phase2",
        &pot12_1,
        &pot12_final,
        "-v",
    ]);

    // Groth16 setup
    let zkey_0 = p("circuit_0000.zkey");
    let zkey_1 = p("circuit_0001.zkey");
    let vkey = p("verification_key.json");
    snarkjs(&[
        "snarkjs",
        "groth16",
        "setup",
        &r1cs_path,
        &pot12_final,
        &zkey_0,
    ]);
    snarkjs(&[
        "snarkjs",
        "zkey",
        "contribute",
        &zkey_0,
        &zkey_1,
        "--name=test",
        "-v",
        "-e=random",
    ]);
    snarkjs(&[
        "snarkjs",
        "zkey",
        "export",
        "verificationkey",
        &zkey_1,
        &vkey,
    ]);

    // Prove and verify
    let proof = p("proof.json");
    let public_json = p("public.json");
    snarkjs(&[
        "snarkjs",
        "groth16",
        "prove",
        &zkey_1,
        &wtns_path,
        &proof,
        &public_json,
    ]);
    snarkjs(&["snarkjs", "groth16", "verify", &vkey, &public_json, &proof]);
}

/// Integration test: compile a circuit through the Plonkish pipeline and export to JSON.
#[test]
fn test_plonkish_json_export_roundtrip() {
    use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program: ir::types::IrProgram =
        IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    compiler.system.verify().unwrap();

    let json = constraints::write_plonkish_json(&compiler.system);
    constraints::validate_plonkish_json(&json).expect("validation failed");

    // Verify structure
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "achronyme-plonkish-v1");
    assert!(parsed["num_rows"].as_u64().unwrap() > 0);
    assert!(parsed["num_advice"].as_u64().unwrap() > 0);
    assert!(!parsed["gates"].as_array().unwrap().is_empty());
    assert!(!parsed["copies"].as_array().unwrap().is_empty());
}

/// snarkjs r1cs info + wtns check integration test.
#[test]
fn test_snarkjs_r1cs_info() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }

    use compiler::r1cs_backend::R1CSCompiler;
    use compiler::witness_gen::WitnessGenerator;
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program: ir::types::IrProgram =
        IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();
    let r1cs_path = p("circuit.r1cs");
    let wtns_path = p("witness.wtns");

    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();

    snarkjs(&["snarkjs", "r1cs", "info", &r1cs_path]);
    snarkjs(&["snarkjs", "wtns", "check", &r1cs_path, &wtns_path]);
}
