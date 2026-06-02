use super::*;

/// SHA-256 compile probe — does circomlib's `sha256compression`
/// now make it through the Artik lift end-to-end?
///
/// Fase 5.1 closed the two historical blockers: array parameters
/// (`hin[256]`, `inp[512]` bound at call sites) and array-literal
/// initializers (`var k[64] = [...]` inside `sha256K`). Running
/// this un-ignored will either pass outright or surface whatever
/// remains — e.g. more exotic bit-manipulation shapes the lift
/// doesn't cover yet. Kept separate from the focused lift tests so
/// failures don't mask simpler regressions.
#[test]
#[ignore = "SHA-256 compile probe — run with --ignored to check Fase 5 completeness"]
fn sha256_64_compiles_via_artik_lift() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let _ = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
}

/// SHA-256 R1CS probe — reports where the pipeline breaks when
/// going past lowering: instantiate, optimize, or R1CS build.
/// Does NOT provide a correct witness — the goal is only to
/// exercise the structural pipeline and surface constraint count
/// or the first hard error (budget, memory, unsupported node).
///
/// Current state (post const-dedup + peephole const-fold fix):
/// the OOM is gone — peak RSS stays around 545 MB (vs. 6.6 GB
/// before the fix). But the probe still fails to complete within
/// practical time budgets: `instantiate` has run >25 min without
/// producing the `[instantiate]` print. The root cause is
/// architectural, not memory-bound: `Sha256(64)` has deeply
/// nested loops (64 rounds × SigmaPlus(48) × SmallSigma0/1 with
/// 32-bit decomposes) that our pipeline unrolls fully into flat
/// SSA during instantiate. Circom avoids this by keeping
/// templates abstract until final R1CS emission. On lighter
/// circuits (Poseidon/MiMC/EdDSA) Achronyme beats circom ≥10×,
/// but bit-heavy nested circuits like SHA-256 expose the gap.
///
/// Follow-up (post-beta.20): lazy unrolling (keep `CircuitNode::For`
/// until R1CS backend) or template instancing with sub-tree
/// sharing — see `project_instantiate_refactor.md`.
#[test]
#[ignore = "SHA-256 R1CS probe — diagnostic only; hangs during instantiate due to unrolling amplification"]
fn sha256_64_r1cs_probe() {
    use std::collections::HashSet;
    use std::time::Instant;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("  [compile]     {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    eprintln!(
        "  [instantiate] {:?}  instructions={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "  [optimize]    {:?}  instructions={}",
        t2.elapsed(),
        program.len()
    );

    // Build R1CS without an inputs map — constraints still get emitted,
    // the witness will just be wrong. We only care whether the pipeline
    // survives to produce a constraint system.
    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let result = rc.compile_ir_with_witness(&program, &inputs);
    eprintln!("  [r1cs build]  {:?}", t3.elapsed());

    match result {
        Ok(_w) => eprintln!("  ✓ R1CS built: constraints={}", rc.cs.num_constraints()),
        Err(e) => eprintln!("  ✗ R1CS failed: {e}"),
    }
}
