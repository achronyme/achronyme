use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

/// Compile a circom circuit and return constraint counts at three
/// optimisation levels:
/// - `before_opt`  -- raw R1CS output, no optimization.
/// - `after_o1`    -- after `optimize_r1cs()` (O1 linear elimination).
/// - `after_o2_s`  -- after `optimize_r1cs_o2_sparse()` (sparse DEDUCE).
///
/// The sparse path is measured on a clone of the pre-opt constraint
/// vec so the live R1CSCompiler keeps its O1-substitution map for
/// witness verification.
pub(super) fn compile_and_measure(
    name: &str,
    circom_file: &str,
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> (usize, usize, usize) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let tp = std::time::Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{name} compilation failed: {e}"));
    let t_lower = tp.elapsed();

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let tp = std::time::Instant::now();
    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{name} instantiation failed: {e}"));
    let t_inst = tp.elapsed();

    let tp = std::time::Instant::now();
    ir::passes::optimize(&mut program);
    let t_opt = tp.elapsed();

    let tp = std::time::Instant::now();
    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
            .unwrap_or_else(|e| panic!("{name} witness failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }
    let t_wit = tp.elapsed();

    let tp = std::time::Instant::now();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let mut witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("{name} R1CS failed: {e}"));
    let t_r1cs = tp.elapsed();

    let before = compiler.cs.num_constraints();

    // Snapshot the unoptimised constraint set for the sparse path so
    // we can measure it independently of the live R1CSCompiler.
    let pre_opt_constraints: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
        compiler.cs.constraints().to_vec();
    let num_pub_inputs = compiler.cs.num_pub_inputs();

    let tp = std::time::Instant::now();
    let stats = compiler.optimize_r1cs();
    let after_o1 = stats.constraints_after;
    let t_r1cs_opt = tp.elapsed();

    // Run sparse O2 on the snapshot. Bypasses R1CSCompiler entirely
    // -- the result feeds the constraint-count comparison only;
    // witness fixup keeps using the O1 substitution map below.
    let tp = std::time::Instant::now();
    let mut sparse_constraints = pre_opt_constraints;
    let (_subs, sparse_stats) =
        constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
    let after_o2_s = sparse_stats.constraints_after;
    let t_r1cs_o2_sparse = tp.elapsed();

    // Re-fill substituted wires
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }

    // Verify optimized system (O1 path -- the one with a fixed-up
    // witness). Sparse O2 produces a different constraint set whose
    // own substitution map we discarded; re-verifying it is not in
    // scope here (covered by sparse_* unit tests in r1cs_optimize).
    compiler
        .cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("{name} verification FAILED after optimization: {e}"));

    eprintln!(
        "||  {name:24} lower={:.0}ms inst={:.0}ms opt={:.0}ms wit={:.0}ms r1cs={:.0}ms r1csO1={:.0}ms r1csO2s={:.0}ms nodes={}",
        t_lower.as_secs_f64() * 1000.0,
        t_inst.as_secs_f64() * 1000.0,
        t_opt.as_secs_f64() * 1000.0,
        t_wit.as_secs_f64() * 1000.0,
        t_r1cs.as_secs_f64() * 1000.0,
        t_r1cs_opt.as_secs_f64() * 1000.0,
        t_r1cs_o2_sparse.as_secs_f64() * 1000.0,
        prove_ir.body.len(),
    );

    (before, after_o1, after_o2_s)
}

/// Witness-less variant of `compile_and_measure` for circuits whose
/// witness path needs domain-specific inputs the benchmark can't
/// fabricate (e.g. EdDSAVerifier requires a valid signature). Builds
/// R1CS without a witness, runs O1 + sparse-O2 against the resulting
/// constraint set, and reports the same `(before, after_o1, after_o2_s)`
/// triple. Skips `cs.verify` because no witness exists.
pub(super) fn compile_and_measure_witnessless(
    name: &str,
    circom_file: &str,
) -> (usize, usize, usize) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let tp = std::time::Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{name} compilation failed: {e}"));
    let t_lower = tp.elapsed();

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let tp = std::time::Instant::now();
    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{name} instantiation failed: {e}"));
    let t_inst = tp.elapsed();

    let tp = std::time::Instant::now();
    ir::passes::optimize(&mut program);
    let t_opt = tp.elapsed();

    let tp = std::time::Instant::now();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler
        .compile_ir(&program)
        .unwrap_or_else(|e| panic!("{name} R1CS compile failed: {e}"));
    let t_r1cs = tp.elapsed();

    let before = compiler.cs.num_constraints();

    let pre_opt_constraints: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
        compiler.cs.constraints().to_vec();
    let num_pub_inputs = compiler.cs.num_pub_inputs();

    let tp = std::time::Instant::now();
    let stats = compiler.optimize_r1cs();
    let after_o1 = stats.constraints_after;
    let t_r1cs_opt = tp.elapsed();

    let tp = std::time::Instant::now();
    let mut sparse_constraints = pre_opt_constraints;
    let (_subs, sparse_stats) =
        constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
    let after_o2_s = sparse_stats.constraints_after;
    let t_r1cs_o2_sparse = tp.elapsed();

    eprintln!(
        "||  {name:24} lower={:.0}ms inst={:.0}ms opt={:.0}ms r1cs={:.0}ms r1csO1={:.0}ms r1csO2s={:.0}ms nodes={} (witness-less)",
        t_lower.as_secs_f64() * 1000.0,
        t_inst.as_secs_f64() * 1000.0,
        t_opt.as_secs_f64() * 1000.0,
        t_r1cs.as_secs_f64() * 1000.0,
        t_r1cs_opt.as_secs_f64() * 1000.0,
        t_r1cs_o2_sparse.as_secs_f64() * 1000.0,
        prove_ir.body.len(),
    );

    (before, after_o1, after_o2_s)
}

/// Format and print a benchmark row.
pub(super) fn print_row(
    name: &str,
    b: usize,
    a: usize,
    cir_o0: &str,
    cir_o1: &str,
    cir_o2: &str,
    ms: f64,
) {
    eprintln!(
        "║ {:26} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5.0}ms ║",
        name,
        b,
        a,
        cir_o0,
        cir_o1,
        cir_o2,
        b - a,
        ms,
    );
}
