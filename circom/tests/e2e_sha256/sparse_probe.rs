use super::*;

/// SHA-256(64) sparse-DEDUCE probe.
///
/// Diagnostic-only counterpart to `sha256_64_lysis_hard_gate` that
/// validates whether sparse-clustered DEDUCE (`optimize_r1cs_o2_sparse`)
/// recovers any constraints O1 alone misses on a real bit-heavy
/// circuit.
///
/// The dense `optimize_r1cs_o2` is intentionally NOT exercised:
/// SHA-256(64) generates `~k x q` `FieldElement`s with both dimensions
/// near 60k (~100 GB) and would OOM on most hosts. The sparse path is
/// the whole point of this probe.
///
/// Steps:
///
///   1. Compile (~47s, dominated by circom lowering).
///   2. Build R1CS (witness-less, like the hard-gate).
///   3. Run O1 once -- record constraint count.
///   4. Run O2-sparse on a snapshot of the post-O1 constraints --
///      record constraint count.
///   5. Print O1 -> O2-sparse delta and the gap vs the circom 2.2.3
///      O2 baseline (29,014).
///
/// Stays `#[ignore]`d for the same reason the hard-gate is: ~47s of
/// circom lowering plus a few hundred ms of sparse DEDUCE on top.
/// Run with
/// `cargo test ... --ignored sha256_64_o2_sparse_probe -- --nocapture`.
#[test]
#[ignore = "SHA-256(64) sparse-DEDUCE probe -- compile is ~47s on this host. Run with `--ignored sha256_64_o2_sparse_probe -- --nocapture` to capture the O1 -> O2-sparse delta."]
fn sha256_64_o2_sparse_probe() {
    use std::collections::HashSet;
    use std::time::Instant;

    // circom 2.2.3 baselines on test/circomlib/sha256_test.circom.
    // Pin to a specific circom version because counts drift across
    // releases; recapture if the toolchain bumps.
    const CIRCOM_O1: usize = 31_264;
    const CIRCOM_O2: usize = 29_014;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("[compile]      {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    eprintln!(
        "[instantiate]  {:?}  ir_inst={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[ir-opt]       {:?}  ir_inst={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_opt = rc.cs.num_constraints();
    eprintln!("[r1cs build]   {:?}  constraints={pre_opt}", t3.elapsed());
    let num_pub_inputs = rc.cs.num_pub_inputs();

    // optimize_r1cs is the cluster-based driver. The greedy
    // implementation is preserved as the per-cluster fallback for
    // clusters above CLUSTER_FALLBACK_THRESHOLD.
    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "[r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
    );

    // Snapshot post-O1 constraints; optimize_o2_sparse internally
    // reruns O1 (no-op on already-O1 input) then enters its
    // decompose + DEDUCE outer loop. Any extra reductions surface as
    // a delta vs post_o1.
    let post_o1_snapshot: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
        rc.cs.constraints().to_vec();

    let t5 = Instant::now();
    let mut sparse_constraints = post_o1_snapshot;
    let (_subs, sparse_stats) =
        constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
    let post_o2_sparse = sparse_stats.constraints_after;
    eprintln!(
        "[r1cs O2-sparse] {:?}  constraints={post_o2_sparse}  delta_vs_O1={:+}  vars_eliminated={}",
        t5.elapsed(),
        post_o2_sparse as i64 - post_o1 as i64,
        sparse_stats.variables_eliminated,
    );

    let delta_o1_vs_o2 = post_o1 as i64 - CIRCOM_O2 as i64;
    let pct_o1_vs_o2 = (delta_o1_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;
    let delta_o2s_vs_o2 = post_o2_sparse as i64 - CIRCOM_O2 as i64;
    let pct_o2s_vs_o2 = (delta_o2s_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;

    eprintln!("\n-- circom 2.2.3 baseline --");
    eprintln!("  --O1 = {CIRCOM_O1}");
    eprintln!("  --O2 = {CIRCOM_O2}");

    eprintln!("\n-- achronyme vs circom O2 --");
    eprintln!("  achronyme pre-opt    = {pre_opt}");
    eprintln!("  achronyme post-O1    = {post_o1}");
    eprintln!("  achronyme post-O2-s  = {post_o2_sparse}");
    eprintln!(
        "  achO1   vs cirO2 ({CIRCOM_O2})  -> delta = {delta_o1_vs_o2:+}  ({pct_o1_vs_o2:+.1}%)"
    );
    eprintln!(
        "  achO2-s vs cirO2 ({CIRCOM_O2})  -> delta = {delta_o2s_vs_o2:+}  ({pct_o2s_vs_o2:+.1}%)"
    );

    eprintln!("\n[total] {:?}", total.elapsed());
}
