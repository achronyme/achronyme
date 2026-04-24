//! Phase-by-phase timing harness for the Circom → R1CS pipeline.
//!
//! Run with:
//!   cargo test -p circom --release --test perf_profile -- --ignored --nocapture
//!
//! Each test exercises one circuit and prints wall time for every phase:
//!   - lower      (compile_file: parse + analysis + Circom lowering)
//!   - instantiate (ProveIR → SSA IR)
//!   - ir_optimize (IR-level passes)
//!   - witness    (off-circuit witness hint computation)
//!   - r1cs_emit  (SSA IR → R1CS constraints)
//!   - optimize_o1 (linear elimination fixpoint)
//!
//! The goal is to identify which phase dominates for each circuit shape
//! (small sub-template, repeated sub-template, deep composition).

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

/// Profile a single Circom circuit through the full pipeline.
/// Returns a vec of `(phase_name, millis)` pairs.
fn profile_circuit(
    circom_file: &str,
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> Vec<(&'static str, f64)> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let mut timings: Vec<(&'static str, f64)> = Vec::new();

    let t = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile_file failed: {e}"));
    timings.push(("lower", t.elapsed().as_secs_f64() * 1000.0));

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let t = Instant::now();
    let mut program = prove_ir
        .instantiate_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    timings.push(("instantiate", t.elapsed().as_secs_f64() * 1000.0));

    let t = Instant::now();
    ir::passes::optimize(&mut program);
    timings.push(("ir_optimize", t.elapsed().as_secs_f64() * 1000.0));

    let t = Instant::now();
    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
            .unwrap_or_else(|e| panic!("witness failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }
    timings.push(("witness", t.elapsed().as_secs_f64() * 1000.0));

    let t = Instant::now();
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let mut witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("r1cs emit failed: {e}"));
    let pre_opt = r1cs_compiler.cs.num_constraints();
    timings.push(("r1cs_emit", t.elapsed().as_secs_f64() * 1000.0));

    let t = Instant::now();
    let stats = r1cs_compiler.optimize_r1cs();
    if let Some(subs) = &r1cs_compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    timings.push(("optimize_o1", t.elapsed().as_secs_f64() * 1000.0));

    let post_opt = r1cs_compiler.cs.num_constraints();

    eprintln!(
        "  constraints: {pre_opt} → {post_opt} (O1 rounds={}, elim={}, dedup={}, trivial={})",
        stats.rounds, stats.variables_eliminated, stats.duplicates_removed, stats.trivial_removed,
    );

    timings
}

fn report(name: &str, circom_file: &str, inputs: HashMap<String, FieldElement<Bn254Fr>>) {
    eprintln!("\n=== {name} ===");
    // Warm up + measure 3 times, report min.
    let mut runs: Vec<Vec<(&'static str, f64)>> = Vec::new();
    for _ in 0..3 {
        runs.push(profile_circuit(circom_file, &inputs));
    }

    let phase_names: Vec<&'static str> = runs[0].iter().map(|(n, _)| *n).collect();
    eprintln!(
        "  {:<14} {:>10} {:>10} {:>10} {:>8}",
        "phase", "min(ms)", "med(ms)", "max(ms)", "%total"
    );

    let mut totals = vec![0.0f64; phase_names.len()];
    for (i, phase) in phase_names.iter().enumerate() {
        let mut vals: Vec<f64> = runs.iter().map(|r| r[i].1).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        totals[i] = vals[0]; // min
        eprintln!(
            "  {:<14} {:>10.2} {:>10.2} {:>10.2}",
            phase, vals[0], vals[1], vals[2]
        );
    }
    let total: f64 = totals.iter().sum();
    eprintln!("  {:<14} {:>10.2}", "TOTAL(min)", total);
    for (i, phase) in phase_names.iter().enumerate() {
        let pct = 100.0 * totals[i] / total;
        eprintln!("  {:<14} {:>7.1}%", phase, pct);
    }
}

#[test]
#[ignore]
fn perf_escalarmulany_254() {
    let mut inputs = HashMap::new();
    for i in 0..254 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    report(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        inputs,
    );
}

#[test]
#[ignore]
fn perf_mimc_sponge_2() {
    let mut inputs = HashMap::new();
    inputs.insert("ins_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    inputs.insert("ins_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    inputs.insert("k".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    report(
        "MiMCSponge(2, 220, 1)",
        "test/circomlib/mimcsponge_test.circom",
        inputs,
    );
}

#[test]
#[ignore]
fn perf_num2bits_8() {
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(13));
    report("Num2Bits(8)", "test/circom/num2bits_8.circom", inputs);
}
