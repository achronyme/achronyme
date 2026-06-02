use std::collections::HashMap;

use circom::{compile_template_library, lower_library_template};
use ir_forge::types::FieldConst;
use memory::{Bn254Fr, FieldElement};

use super::common::{lib_dirs, workspace_root};
use super::stats::{collect_circuit_node_stats, collect_extended_stats};

#[test]
#[ignore]
fn probe_lower_library_template_sha256_8() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Sha256(8) — standalone via lower_library_template + Lysis");
    eprintln!("================================================================");

    let mut captures = HashMap::new();
    captures.insert("nBits".to_string(), FieldConst::from_u64(8));

    let lower_result = lower_library_template(&library, "Sha256", captures.clone())
        .expect("lower_library_template Sha256(8) succeeds");

    let stats = collect_circuit_node_stats(&lower_result.prove_ir.body);
    stats.print("Sha256(8)");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = captures
        .keys()
        .map(|k| (k.clone(), FieldElement::<Bn254Fr>::from_u64(8)))
        .collect();

    let lysis_result = lower_result
        .prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &lower_result.output_names);
    match lysis_result {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_lower_library_template_sha256_64() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE C — lower_library_template (For-preserving) for Sha256(64)");
    eprintln!("================================================================");
    eprintln!();

    let mut captures = HashMap::new();
    captures.insert("nBits".to_string(), FieldConst::from_u64(64));

    let lower_result = lower_library_template(&library, "Sha256", captures.clone())
        .expect("lower_library_template Sha256(64) succeeds");

    eprintln!("[ProveIR header]");
    eprintln!("  body.len()     = {}", lower_result.prove_ir.body.len());
    eprintln!("  output_names   = {}", lower_result.output_names.len());
    eprintln!();

    eprintln!("[ProveIR CircuitNode stats]");
    let stats = collect_circuit_node_stats(&lower_result.prove_ir.body);
    stats.print("for-preserving");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = captures
        .keys()
        .map(|k| (k.clone(), FieldElement::<Bn254Fr>::from_u64(64)))
        .collect();

    let extended = lower_result
        .prove_ir
        .instantiate_with_outputs_extended::<Bn254Fr>(&fe_captures, &lower_result.output_names)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("[ExtendedInstruction stats]");
    let ext_stats = collect_extended_stats(&extended.body);
    ext_stats.print("for-preserving");

    eprintln!();
    eprintln!("[Driving through Lysis]");
    let lysis_result = lower_result
        .prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &lower_result.output_names);
    match lysis_result {
        Ok(prog) => {
            eprintln!("  Lysis OK — {} flat instructions", prog.len());
            eprintln!("    For nodes preserved: {}", stats.n_for);
            eprintln!("    LoopUnrolls produced: {}", ext_stats.n_loop_unroll);
        }
        Err(e) => {
            eprintln!("  Lysis FAILED: {e}");
            eprintln!("    For nodes preserved: {}", stats.n_for);
            eprintln!("    LoopUnrolls produced: {}", ext_stats.n_loop_unroll);
        }
    }
}
