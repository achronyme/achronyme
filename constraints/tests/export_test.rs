use constraints::r1cs::{ConstraintSystem, LinearCombination};
use constraints::{write_r1cs, write_wtns};
use memory::FieldElement;

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
    let data = write_r1cs(&cs);

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
    let data = write_wtns(&witness);

    assert_eq!(&data[0..4], b"wtns");
    assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 2);

    // Values section size = 4 * 32 = 128
    // Section 2 header: after file header (12) + sec1 header (12) + sec1 body (40) = 64
    let sec2_offset = 12 + 12 + 40;
    let sec2_size = u64::from_le_bytes(
        data[sec2_offset + 4..sec2_offset + 12].try_into().unwrap(),
    );
    assert_eq!(sec2_size, 128);
}

#[test]
fn test_r1cs_and_wtns_consistent_wire_count() {
    let (cs, witness) = make_mul_circuit();
    let r1cs_data = write_r1cs(&cs);
    let wtns_data = write_wtns(&witness);

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
    let program = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let r1cs_data = write_r1cs(&compiler.cs);
    assert_eq!(&r1cs_data[0..4], b"r1cs");

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    let wtns_data = write_wtns(&witness);
    assert_eq!(&wtns_data[0..4], b"wtns");
}

/// Full Groth16 integration test: powers of tau → setup → prove → verify.
/// Requires node.js and snarkjs to be installed (npx snarkjs).
#[test]
#[ignore]
fn test_snarkjs_groth16_full() {
    use compiler::r1cs_backend::R1CSCompiler;
    use compiler::witness_gen::WitnessGenerator;
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let dir = "/tmp/achronyme_groth16_test";
    std::fs::create_dir_all(dir).unwrap();

    let r1cs_path = format!("{dir}/circuit.r1cs");
    let wtns_path = format!("{dir}/witness.wtns");

    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs)).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness)).unwrap();

    let run = |args: &[&str]| {
        let output = std::process::Command::new("npx")
            .args(args)
            .output()
            .expect("npx not available");
        assert!(
            output.status.success(),
            "command failed: npx {}\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    // Powers of Tau ceremony
    let pot12 = format!("{dir}/pot12_0000.ptau");
    let pot12_1 = format!("{dir}/pot12_0001.ptau");
    let pot12_final = format!("{dir}/pot12_final.ptau");
    run(&["snarkjs", "powersoftau", "new", "bn128", "12", &pot12, "-v"]);
    run(&["snarkjs", "powersoftau", "contribute", &pot12, &pot12_1, "--name=test", "-v", "-e=random"]);
    run(&["snarkjs", "powersoftau", "prepare", "phase2", &pot12_1, &pot12_final, "-v"]);

    // Groth16 setup
    let zkey_0 = format!("{dir}/circuit_0000.zkey");
    let zkey_1 = format!("{dir}/circuit_0001.zkey");
    let vkey = format!("{dir}/verification_key.json");
    run(&["snarkjs", "groth16", "setup", &r1cs_path, &pot12_final, &zkey_0]);
    run(&["snarkjs", "zkey", "contribute", &zkey_0, &zkey_1, "--name=test", "-v", "-e=random"]);
    run(&["snarkjs", "zkey", "export", "verificationkey", &zkey_1, &vkey]);

    // Prove and verify
    let proof = format!("{dir}/proof.json");
    let public_json = format!("{dir}/public.json");
    run(&["snarkjs", "groth16", "prove", &zkey_1, &wtns_path, &proof, &public_json]);
    run(&["snarkjs", "groth16", "verify", &vkey, &public_json, &proof]);

    // Cleanup
    std::fs::remove_dir_all(dir).ok();
}

/// snarkjs integration test (requires npx/snarkjs installed).
#[test]
#[ignore]
fn test_snarkjs_r1cs_info() {
    use compiler::r1cs_backend::R1CSCompiler;
    use compiler::witness_gen::WitnessGenerator;
    use ir::IrLowering;
    use std::collections::HashMap;

    let source = "assert_eq(a * b, out)";
    let program = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let r1cs_path = "/tmp/achronyme_test.r1cs";
    let wtns_path = "/tmp/achronyme_test.wtns";

    std::fs::write(r1cs_path, write_r1cs(&compiler.cs)).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    std::fs::write(wtns_path, write_wtns(&witness)).unwrap();

    // snarkjs r1cs info
    let output = std::process::Command::new("npx")
        .args(["snarkjs", "r1cs", "info", r1cs_path])
        .output()
        .expect("npx snarkjs not available");
    assert!(output.status.success(), "r1cs info failed: {}", String::from_utf8_lossy(&output.stderr));

    // snarkjs wtns check
    let output = std::process::Command::new("npx")
        .args(["snarkjs", "wtns", "check", r1cs_path, wtns_path])
        .output()
        .expect("npx snarkjs not available");
    assert!(output.status.success(), "wtns check failed: {}", String::from_utf8_lossy(&output.stderr));

    std::fs::remove_file(r1cs_path).ok();
    std::fs::remove_file(wtns_path).ok();
}
