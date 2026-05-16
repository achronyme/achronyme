//! E2E test harness for Circom → ProveIR → R1CS pipeline.
//!
//! Scans `test/circom/*.circom` files and runs each through three tiers:
//!   1. **Parse**: `parser::parse_circom()` succeeds
//!   2. **Lower**: `compile_to_prove_ir()` succeeds (parse + analysis + lowering)
//!   3. **R1CS**:  instantiate → optimize → R1CS compile → verify
//!
//! Each `.circom` file may have a companion `.inputs.toml` with signal values.
//! Without inputs, tier 3 is skipped.
//!
//! TOML format:
//! ```toml
//! [inputs]
//! in = 42          # scalar signal
//! in = [3, 10]     # array → in_0=3, in_1=10
//!
//! [expected]
//! constraints = 17 # optional: assert constraint count
//! ```

mod common;
use common::*;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

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

/// SHA-256(8) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints.
///
/// Smallest legal SHA-256 input — exercises the round + finalizer
/// with minimal frontend wiring overhead. Useful as a fast regression
/// check at one-block scale; a regression that doesn't surface here
/// (vs. (64) where it would dominate the perf/correctness signal)
/// is by definition specific to the larger-message wiring path.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_8_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_8_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(8)",
        "test/circomlib/sha256_8_test.circom",
        8,
        28_953,
        Duration::from_secs(120),
    );
}

/// SHA-256(16) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints (same as (8) and
/// (32) — single 512-bit block dominates the post-O2 count; only
/// the frontend wiring scales with `nBits`, all of which O2 eats).
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_16_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_16_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(16)",
        "test/circomlib/sha256_16_test.circom",
        16,
        28_953,
        Duration::from_secs(120),
    );
}

/// SHA-256(32) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints. Mid-size variant:
/// still one 512-bit block but with more frontend `Num2Bits` wiring
/// than (8)/(16). The wider input range stresses Walker
/// per-iteration body sharing on the `for(i=0..32) { ... in[i] ... }`
/// expansion.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_32_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_32_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(32)",
        "test/circomlib/sha256_32_test.circom",
        32,
        28_953,
        Duration::from_secs(120),
    );
}

/// **SHA-256(64) HARD GATE.** SHA-256(64) through the Lysis
/// pipeline (`ProveIR::instantiate_lysis_with_outputs`) must:
///
/// 1. Complete end-to-end (compile + instantiate + IR-optimize +
///    R1CS-build + R1CS-O1) in under 120 seconds wall-clock. The
///    legacy `sha256_64_r1cs_probe` hangs >25 minutes; Lysis
///    avoids that by emitting `ExtendedInstruction::LoopUnroll`
///    nodes the InterningSink hash-cons across iterations.
/// 2. Produce a post-O1 R1CS constraint count within +/-15% of
///    circom 2.2.3's `--O2` baseline. The bound is intentionally
///    looser than the plan's +/-5% because (a) we target BN254
///    while circom canonically reports for 254-bit, (b) achronyme
///    O1 matches or beats circom O2 on Poseidon/MiMC but bit-heavy
///    circuits like SHA-256 may carry a small DEDUCE-shaped
///    residual -- DEDUCE itself is unscalable here (k x q monomial
///    matrix grows to tens of GB on SHA-256) so we accept the
///    residual.
///
/// Indicative numbers from current host:
///
/// ```text
///   [compile]       ~13s
///   [instantiate]   ~1.2s  instructions=207,332
///   [ir-optimize]   ~93ms  instructions=199,932
///   [r1cs build]    ~46ms  constraints=70,623   (40,337 linear + 29,972 quadratic)
///   [r1cs O1]       ~710ms constraints=29,790   (eliminates 40,832 vars in 2 rounds)
/// ```
///
/// achronyme post-O1 (29,790) sits 2.7% above circom O2 (29,014),
/// well within the ±15% tolerance.
///
/// Notes:
///
/// - Uses arbitrary inputs. We care about structural completion,
///   not witness correctness (the constraint count doesn't depend
///   on input values).
/// - Output lines are `eprintln`-style diagnostic -- they surface
///   wall-clock + instruction/constraint counts. If the gate
///   fails, these give the first-look picture.
/// - DEDUCE (`optimize_r1cs_o2`) is intentionally NOT run: the
///   monomial x constraint matrix for SHA-256(64) is roughly
///   60k x 60k field elements (~100 GB), unscalable on this
///   circuit. The constraint benchmark `r1cs_optimization_benchmark`
///   exercises O2 on smaller circuits where it converges quickly.
///
/// **Architectural invariants this gate depends on**:
///
///   - Lifted-template frame overflow handling (the lifter splits
///     captures across template boundaries).
///   - Live-set > 64 captures supported via heap-backed slots.
///   - `SymbolicIndexedEffectNotEmittable` does not fire after a
///     mid-emission split (walker_const forwards across splits).
///   - Cold WitnessCall inputs route through `EmitWitnessCallHeap`,
///     mixing reg/slot operands.
///   - Validator rule 9 pre-initialises template capture regs and
///     tracks `StoreHeap` reads and `LoadHeap` writes.
///   - Default `MaxCallDepth` is high enough for the round chain
///     (currently 8192).
///   - `const_fold` keys its expansion by instruction index, not
///     `result_var`, so alias-Decompose doesn't produce dangling
///     SsaVars.
///   - The gate calls `optimize_r1cs()` — without it, the 40k+
///     linear constraints that O1 eliminates inflate the count
///     well beyond the +/-15% tolerance.
///   - `lysis::bytecode::validate` is gated behind
///     `cfg(debug_assertions)` so release-mode instantiate stays
///     fast.
///
/// **Remaining work (independent of this gate)**:
///
///   - **Compile time** ~13s on this host. Tracked as a separate
///     workstream.
///   - **Lazy-reload-without-recycling frame growth** — placeholder
///     in `ir-forge/tests/walker_adversarial.rs`; not hit by
///     SHA-256(64), would surface for larger circuits.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host (down from ~47s pre-perf work). Run with `--ignored sha256_64_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path. Once compile time drops further, this can become a CI-default gate."]
fn sha256_64_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(64)",
        "test/circomlib/sha256_test.circom",
        64,
        29_014,
        Duration::from_secs(120),
    );
}

/// Diagnostic instrumentation for the SHA-256(64) constraint-parity gap.
///
/// The hard-gate (`sha256_64_lysis_hard_gate`) reports 70,623 constraints
/// post-IR-optimize, *pre*-R1CS-optimize. circom 2.2.3 with `--O2` on the
/// same circuit reports 29,014 (0 linear, 29,014 non-linear). This test
/// runs the full pipeline through `optimize_r1cs()` (O1 -- linear
/// elimination only, no DEDUCE) and prints:
///
///   - constraint count + shape histogram pre-optimize
///   - constraint count + shape histogram post-O1
///   - the gap vs circom O0/O1/O2
///
/// O2 (DEDUCE Gaussian elimination) is intentionally skipped -- the
/// monomial x constraint matrix is `~k x q` `FieldElement`s where both
/// dimensions reach ~60k for SHA-256(64), exceeding 16 GB of RAM.
/// circom's own progression (O0->O1 kills 171k linears, O1->O2 only ~2k
/// more) suggests O1 closes most of the gap by itself.
///
/// Shape categories follow the `is_linear` predicate from
/// `r1cs_optimize::predicates`: a constraint with one of A/B simplifying
/// to a constant counts as "linear", everything else gets bucketed by
/// term-count of A,B,C. The `(|A|,|B|,|C|)` histogram surfaces dominant
/// patterns (e.g. `(1,1,0)` for `x*x=0`-shaped, `(1,2,0)` for bool
/// checks, `(1,N,0)` for bit-decomposition equality).
///
/// `#[ignore]`d -- compile alone is ~47s on this host.
#[test]
#[ignore = "SHA-256(64) constraint shape diagnostic -- compile is ~47s. Run with `--ignored sha256_64_constraint_breakdown` to capture pre/post-O1 distributions."]
fn sha256_64_constraint_breakdown() {
    use std::collections::HashSet;
    use std::time::Instant;

    // circom 2.2.3 baseline from
    // `circom test/circomlib/sha256_test.circom --r1cs --O{0,1,2}`.
    const CIRCOM_O0: usize = 204_576;
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
    let pre_o2 = rc.cs.num_constraints();
    eprintln!("[r1cs build]   {:?}  constraints={pre_o2}", t3.elapsed());

    eprintln!("\n-- PRE-R1CS-O2 shape histogram ----------------------");
    print_constraint_histogram(rc.cs.constraints());

    // Note: we run only O1 (`optimize_r1cs`) here, not O2.
    // For SHA-256(64) the DEDUCE Gaussian elimination in O2 builds a
    // monomial x constraint matrix of order ~60k x 60k field elements,
    // which is ~100 GB and OOMs on a 16 GB host. circom's progression
    // (O0->O1 kills 171k linears, O1->O2 only saves ~2k more) suggests
    // O1 is sufficient for the parity gap on this circuit.
    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "\n[r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}  trivial_removed={}  duplicates_removed={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
        stats.trivial_removed,
        stats.duplicates_removed,
    );
    eprintln!("\n-- O1 round_details (linear_eliminated, newly_linear) ----");
    let total_newly_linear: usize = stats.round_details.iter().map(|(_, n)| n).sum();
    for (i, (lin_elim, newly_lin)) in stats.round_details.iter().enumerate() {
        eprintln!(
            "  round {}: linear_eliminated={lin_elim}  newly_linear={newly_lin}",
            i + 1
        );
    }
    eprintln!("  total newly_linear across rounds = {total_newly_linear}");

    eprintln!("\n-- POST-R1CS-O1 shape histogram ---------------------");
    print_constraint_histogram(rc.cs.constraints());

    eprintln!("\n-- circom 2.2.3 baseline ----------------------------");
    eprintln!("  --O0 = {CIRCOM_O0}");
    eprintln!("  --O1 = {CIRCOM_O1}");
    eprintln!("  --O2 = {CIRCOM_O2}");

    eprintln!("\n-- achronyme vs circom delta ------------------------");
    let delta_vs_o1 = post_o1 as i64 - CIRCOM_O1 as i64;
    let pct_vs_o1 = (delta_vs_o1 as f64 / CIRCOM_O1 as f64) * 100.0;
    let delta_vs_o2 = post_o1 as i64 - CIRCOM_O2 as i64;
    let pct_vs_o2 = (delta_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;
    eprintln!("  achronyme pre-opt   = {pre_o2}");
    eprintln!("  achronyme post-O1   = {post_o1}");
    eprintln!("  vs circom O1 ({CIRCOM_O1})  -> delta = {delta_vs_o1:+}  ({pct_vs_o1:+.1}%)");
    eprintln!("  vs circom O2 ({CIRCOM_O2})  -> delta = {delta_vs_o2:+}  ({pct_vs_o2:+.1}%)");

    eprintln!("\n[total] {:?}", total.elapsed());
}

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

/// SHA-256(64) circom-O2-vs-achronyme-O1 constraint shape diff.
///
/// Read-only diagnostic. Compares the symmetrized
/// `(min(|A|,|B|), max(|A|,|B|), |C|)` histogram of achronyme's
/// post-O1 R1CS against circom 2.2.3's `--O2` output for the same
/// circuit. Surfaces whether the +112c residual is concentrated in
/// any single shape bucket (or one shape family) or spread thinly
/// across many.
///
/// Prerequisite: a circom O2 dump in JSON form. Generate with:
///
/// ```text
/// mkdir -p /tmp/cir-sha256-o2 && \
///   circom test/circomlib/sha256_test.circom --r1cs --O2 \
///     -l test/circomlib -o /tmp/cir-sha256-o2/ && \
///   snarkjs r1cs export json /tmp/cir-sha256-o2/sha256_test.r1cs \
///     /tmp/cir-sha256-o2/sha256_test.json
/// ```
///
/// Decision thresholds (printed at end of run):
/// - `largest_single_bucket >= 50 c` -> ship-relevant lever; drill
///   into the gadget that owns that shape (D4 follow-up).
/// - `top family combined >= 50 c` -> family-level lever; same
///   path.
/// - `spread thinly across >=5 buckets at <=20 c each` -> seventh
///   null pre-flight; archive the chase.
#[test]
#[ignore = "SHA-256(64) histogram-diff vs circom --O2. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256-o2/sha256_test.json (see test docstring). Run with `--ignored sha256_64_circom_o2_histogram_diff -- --nocapture`."]
fn sha256_64_circom_o2_histogram_diff() {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256-o2/sha256_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!(
            "circom O2 JSON dump not found at {CIRCOM_O2_JSON}.\n\
             Generate via:\n  \
             mkdir -p /tmp/cir-sha256-o2 && circom test/circomlib/sha256_test.circom \
             --r1cs --O2 -l test/circomlib -o /tmp/cir-sha256-o2/ && snarkjs r1cs \
             export json /tmp/cir-sha256-o2/sha256_test.r1cs /tmp/cir-sha256-o2/sha256_test.json"
        );
    }

    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    let mut circom_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in constraints_v {
        let arr = c.as_array().expect("constraint triple [A,B,C]");
        let an = arr[0].as_object().map(|m| m.len()).unwrap_or(0);
        let bn = arr[1].as_object().map(|m| m.len()).unwrap_or(0);
        let cn = arr[2].as_object().map(|m| m.len()).unwrap_or(0);
        let key = (an.min(bn), an.max(bn), cn);
        *circom_hist.entry(key).or_insert(0) += 1;
    }
    let circom_total: usize = circom_hist.values().sum();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let _ = rc.optimize_r1cs();

    let mut ach_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in rc.cs.constraints() {
        let a = c.a.simplify();
        let b = c.b.simplify();
        let cc = c.c.simplify();
        let an = a.terms().len();
        let bn = b.terms().len();
        let cn = cc.terms().len();
        let key = (an.min(bn), an.max(bn), cn);
        *ach_hist.entry(key).or_insert(0) += 1;
    }
    let ach_total: usize = ach_hist.values().sum();

    type ShapeKey = (usize, usize, usize);
    type DiffRow = (ShapeKey, usize, usize, i64);

    let mut all_keys: BTreeSet<ShapeKey> = BTreeSet::new();
    all_keys.extend(circom_hist.keys().copied());
    all_keys.extend(ach_hist.keys().copied());

    let mut rows: Vec<DiffRow> = all_keys
        .iter()
        .map(|&k| {
            let cir = *circom_hist.get(&k).unwrap_or(&0);
            let ach = *ach_hist.get(&k).unwrap_or(&0);
            (k, cir, ach, ach as i64 - cir as i64)
        })
        .collect();
    rows.sort_by(|x, y| y.3.abs().cmp(&x.3.abs()).then(x.0.cmp(&y.0)));

    eprintln!("\n=== SHA-256(64) post-O1 vs circom --O2 (symmetrized A,B order) ===");
    eprintln!("achronyme post-O1 total = {ach_total}");
    eprintln!("circom --O2     total  = {circom_total}");
    eprintln!(
        "net residual           = {:+} c\n",
        ach_total as i64 - circom_total as i64
    );

    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "(min|A|,max,|C|)", "circomO2", "achO1", "delta(ach-cir)"
    );
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "----------------", "--------", "-----", "--------------"
    );
    for (k, cir, ach, delta) in rows.iter().take(40) {
        eprintln!(
            "  ({:>2},{:>2},{:>2})    {:>12} {:>10} {:>+15}",
            k.0, k.1, k.2, cir, ach, delta
        );
    }

    let total_abs_delta: i64 = rows.iter().map(|r| r.3.abs()).sum();
    let largest = rows[0];
    let top3_pos: i64 = rows.iter().filter(|r| r.3 > 0).take(3).map(|r| r.3).sum();
    let top3_neg: i64 = rows.iter().filter(|r| r.3 < 0).take(3).map(|r| r.3).sum();
    let buckets_with_excess_ge_20 = rows.iter().filter(|r| r.3 >= 20).count();
    let buckets_with_excess_ge_50 = rows.iter().filter(|r| r.3 >= 50).count();

    eprintln!("\n=== divergence summary ===");
    eprintln!(
        "largest_single_bucket  : ({:>2},{:>2},{:>2}) -> delta = {:+} c",
        largest.0 .0, largest.0 .1, largest.0 .2, largest.3
    );
    eprintln!("top_3_positive (we have more)  : Σ = {:+} c", top3_pos);
    eprintln!("top_3_negative (we have fewer) : Σ = {:+} c", top3_neg);
    eprintln!("buckets where excess >= 20 c   : {buckets_with_excess_ge_20}");
    eprintln!("buckets where excess >= 50 c   : {buckets_with_excess_ge_50}");
    eprintln!("Σ |delta| across all buckets   : {} c", total_abs_delta);
    eprintln!(
        "net residual                  : {:+} c",
        ach_total as i64 - circom_total as i64
    );

    eprintln!("\n=== decision threshold ===");
    eprintln!(
        "  largest_single_bucket >= 50 c  -> ship-relevant lever; drill gadget owning shape (D4)"
    );
    eprintln!("  multiple buckets >= 50 c, same family (e.g. all (1,N,*))  -> family-level lever");
    eprintln!(
        "  spread thinly: >=5 buckets at <=20 c each  -> seventh null pre-flight, archive chase"
    );
}

/// Sha256(8) variant of the histogram-diff. Used to test the
/// per-input-bit hypothesis: if the wrapper-only `(1,2,0)` excess
/// scales with `nBits`, achronyme is over-emitting bool-checks
/// proportional to the number of variable input bits.
#[test]
#[ignore = "Sha256(8) histogram diff. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256_8-o2/sha256_8_test.json. Run with `--ignored sha256_8_circom_o2_histogram_diff -- --nocapture`."]
fn sha256_8_circom_o2_histogram_diff() {
    use std::collections::{BTreeMap, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256_8-o2/sha256_8_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!("circom O2 dump not found at {CIRCOM_O2_JSON}");
    }
    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    let mut circom_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in constraints_v {
        let arr = c.as_array().expect("constraint triple [A,B,C]");
        let an = arr[0].as_object().map(|m| m.len()).unwrap_or(0);
        let bn = arr[1].as_object().map(|m| m.len()).unwrap_or(0);
        let cn = arr[2].as_object().map(|m| m.len()).unwrap_or(0);
        let key = (an.min(bn), an.max(bn), cn);
        *circom_hist.entry(key).or_insert(0) += 1;
    }
    let circom_total: usize = circom_hist.values().sum();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_8_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Sha256(8) compile failed: {e}"));
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(8));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let _ = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();

    let mut ach_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in rc.cs.constraints() {
        let an = c.a.simplify().terms().len();
        let bn = c.b.simplify().terms().len();
        let cn = c.c.simplify().terms().len();
        *ach_hist.entry((an.min(bn), an.max(bn), cn)).or_insert(0) += 1;
    }

    let bool_check_circom = circom_hist.get(&(1, 2, 0)).copied().unwrap_or(0);
    let bool_check_ach = ach_hist.get(&(1, 2, 0)).copied().unwrap_or(0);

    eprintln!("\n=== Sha256(8) — achronyme post-O1 vs circom --O2 ===");
    eprintln!("achronyme post-O1   = {post_o1}");
    eprintln!("circom    --O2      = {circom_total}");
    eprintln!(
        "net residual        = {:+} c",
        post_o1 as i64 - circom_total as i64
    );
    eprintln!();
    eprintln!("(1,2,0) bool-check-shape:");
    eprintln!("  circom    --O2 = {bool_check_circom}");
    eprintln!("  achronyme O1   = {bool_check_ach}");
    eprintln!(
        "  delta          = {:+}",
        bool_check_ach as i64 - bool_check_circom as i64
    );
    eprintln!();
    eprintln!("=== reference (from prior runs) ===");
    eprintln!("Sha256(64) full:        ach (1,2,0) = 10309, circom = 10160, Δ = +149");
    eprintln!("Sha256comp(1) standalone: ach (1,2,0) = 10245, circom = 10160, Δ = +85");
    eprintln!("                          wrapper-only Δ on (1,2,0) for nBits=64 = +64");
    eprintln!();
    eprintln!("=== per-input-bit hypothesis ===");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+8 = +93  -> hypothesis CONFIRMED (1c per bit)");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+0 = +85  -> wrapper effect is constant, not per-bit");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+64 = +149 -> wrapper effect is constant 64, masked by nBits coincidence");
}

/// Dump every `IrInstruction::Decompose` in the SHA-256(64) IR
/// program with its `num_bits`, comparing standalone
/// `Sha256compression(1)` to the full `Sha256(64)`. The wrapper-only
/// new Decomposes pinpoint where the per-input-bit bool-checks
/// originate.
#[test]
#[ignore = "Decompose dump for SHA-256 wrapper analysis. Run with `--ignored sha256_decompose_dump -- --nocapture`."]
fn sha256_decompose_dump() {
    use std::collections::{BTreeMap, HashSet};

    fn compile_decompose_hist(
        label: &str,
        fixture_path: &str,
        nbits_capture: Option<u64>,
    ) -> BTreeMap<u32, usize> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(fixture_path);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{label} compile failed: {e}"));

        let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        if let Some(n) = nbits_capture {
            captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
        }
        let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
        let mut program = compile_result
            .prove_ir
            .instantiate_lysis_with_outputs(&captures, &outs)
            .unwrap_or_else(|e| panic!("{label} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        let mut hist: BTreeMap<u32, usize> = BTreeMap::new();
        for inst in &program.instructions {
            if let ir::types::Instruction::Decompose { num_bits, .. } = inst {
                *hist.entry(*num_bits).or_insert(0) += 1;
            }
        }
        eprintln!(
            "[{label}] {} Decompose instructions, num_bits histogram: {:?}",
            hist.values().sum::<usize>(),
            hist
        );
        hist
    }

    let standalone = compile_decompose_hist(
        "Sha256comp(1)",
        "test/circomlib/sha256compression_test.circom",
        None,
    );
    let s8 = compile_decompose_hist("Sha256(8)", "test/circomlib/sha256_8_test.circom", Some(8));
    let s64 = compile_decompose_hist("Sha256(64)", "test/circomlib/sha256_test.circom", Some(64));

    eprintln!("\n=== Decompose num_bits diff (wrapper-only) ===");
    let mut all_keys: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    all_keys.extend(standalone.keys().copied());
    all_keys.extend(s8.keys().copied());
    all_keys.extend(s64.keys().copied());
    eprintln!(
        "{:>10} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "num_bits", "standalone", "Sha256(8)", "Sha256(64)", "wrapper(8)", "wrapper(64)"
    );
    for k in all_keys {
        let std_v = standalone.get(&k).copied().unwrap_or(0);
        let s8_v = s8.get(&k).copied().unwrap_or(0);
        let s64_v = s64.get(&k).copied().unwrap_or(0);
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        if w8 != 0 || w64 != 0 || std_v > 0 {
            eprintln!(
                "{:>10} {:>14} {:>10} {:>10} {:>+14} {:>+14}",
                k, std_v, s8_v, s64_v, w8, w64
            );
        }
    }
}

/// Per-call-site bool-check counter localiser.
///
/// Compiles `Sha256compression(1)`, `Sha256(8)`, and `Sha256(64)`
/// in sequence, snapshots the bool-check emission counters from
/// `zkc::r1cs_backend` (one per call site: RangeCheck, Decompose,
/// And.lhs/rhs, Or.lhs/rhs, Not, Mux.cond, Assert) after each
/// compile, and prints the per-site delta.
///
/// The call site whose delta scales with `nBits` between Sha256(8)
/// and Sha256(64) is the per-input-bit emission site responsible
/// for the +N (1,2,0) constraints in the outer wrapper. Run with
/// the standalone `Sha256compression(1)` baseline subtracted to
/// isolate the wrapper's contribution.
#[test]
#[ignore = "Per-call-site bool-check localiser. Run with `--ignored sha256_boolcheck_site_localiser -- --nocapture`."]
fn sha256_boolcheck_site_localiser() {
    use std::collections::HashSet;
    use zkc::r1cs_backend::{reset_boolcheck_counters, snapshot_boolcheck_counters};

    fn compile_and_snapshot(
        label: &str,
        fixture_path: &str,
        nbits_capture: Option<u64>,
    ) -> [(&'static str, u64); 12] {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(fixture_path);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{label} compile failed: {e}"));

        let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        if let Some(n) = nbits_capture {
            captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
        }
        let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
        let mut program = compile_result
            .prove_ir
            .instantiate_lysis_with_outputs(&captures, &outs)
            .unwrap_or_else(|e| panic!("{label} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        reset_boolcheck_counters();
        let mut rc = R1CSCompiler::<Bn254Fr>::new();
        rc.compile_ir(&program).expect("R1CS compile");
        // optimize is post-emission; counters reflect emission only.
        let _ = rc.optimize_r1cs();
        snapshot_boolcheck_counters()
    }

    let standalone = compile_and_snapshot(
        "Sha256comp(1)",
        "test/circomlib/sha256compression_test.circom",
        None,
    );
    let sha256_8 =
        compile_and_snapshot("Sha256(8)", "test/circomlib/sha256_8_test.circom", Some(8));
    let sha256_64 =
        compile_and_snapshot("Sha256(64)", "test/circomlib/sha256_test.circom", Some(64));

    eprintln!("\n=== bool-check emission counters by call site ===");
    eprintln!(
        "{:>14} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "site", "standalone", "Sha256(8)", "Sha256(64)", "wrapper(8)", "wrapper(64)"
    );
    eprintln!(
        "{:>14} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "----", "----------", "---------", "----------", "----------", "----------"
    );

    for i in 0..12 {
        let (site, std_v) = standalone[i];
        let (_, s8_v) = sha256_8[i];
        let (_, s64_v) = sha256_64[i];
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        eprintln!(
            "{:>14} {:>14} {:>10} {:>10} {:>+14} {:>+14}",
            site, std_v, s8_v, s64_v, w8, w64
        );
    }

    eprintln!("\n=== look for: site where wrapper(64) - wrapper(8) ≈ 56 ===");
    eprintln!("That's the per-variable-input-bit emission site.");
    for i in 0..12 {
        let (site, std_v) = standalone[i];
        let (_, s8_v) = sha256_8[i];
        let (_, s64_v) = sha256_64[i];
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        let scaling = w64 - w8;
        if scaling.abs() >= 5 {
            eprintln!(
                "  {site}: wrapper(64)-wrapper(8) = {scaling:+}  ({} c per extra input bit)",
                scaling as f64 / (64.0 - 8.0)
            );
        }
    }
}

/// Per-block differential: compile `Sha256compression()` standalone
/// (one block, no padding) in achronyme and compare to circom
/// `--O2`. Isolates the cost of the Sha256compression round body
/// from the cost of the outer Sha256 wrapper (input padding,
/// length encoding, paddedIn fan-out).
///
/// `Sha256(64) = padding/length-encoding overhead + Sha256compression(1) + output unpack`.
/// If achronyme matches circom on Sha256compression(1) standalone,
/// the +112 c residual on Sha256(64) lives in the outer wrapper.
/// If achronyme is +N on Sha256compression(1) standalone, the gap
/// is per-block and `n_blocks × N` should match the full-circuit
/// residual.
///
/// Prerequisite: a circom O2 dump in JSON form. Generate with:
///
/// ```text
/// mkdir -p /tmp/cir-sha256comp-o2 && \
///   circom test/circomlib/sha256compression_test.circom --r1cs --O2 \
///     -l test/circomlib -o /tmp/cir-sha256comp-o2/ && \
///   snarkjs r1cs export json \
///     /tmp/cir-sha256comp-o2/sha256compression_test.r1cs \
///     /tmp/cir-sha256comp-o2/sha256compression_test.json
/// ```
#[test]
#[ignore = "Sha256compression(1) per-block differential vs circom --O2. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256comp-o2/sha256compression_test.json. Run with `--ignored sha256compression_perblock_diff -- --nocapture`."]
fn sha256compression_perblock_diff() {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256comp-o2/sha256compression_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!(
            "circom O2 JSON dump not found at {CIRCOM_O2_JSON}.\n\
             Generate via:\n  \
             mkdir -p /tmp/cir-sha256comp-o2 && circom \
             test/circomlib/sha256compression_test.circom --r1cs --O2 \
             -l test/circomlib -o /tmp/cir-sha256comp-o2/ && snarkjs r1cs \
             export json /tmp/cir-sha256comp-o2/sha256compression_test.r1cs \
             /tmp/cir-sha256comp-o2/sha256compression_test.json"
        );
    }

    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    type ShapeKey = (usize, usize, usize);
    type DiffRow = (ShapeKey, usize, usize, i64);

    let mut circom_hist: BTreeMap<ShapeKey, usize> = BTreeMap::new();
    for c in constraints_v {
        let arr = c.as_array().expect("constraint triple [A,B,C]");
        let an = arr[0].as_object().map(|m| m.len()).unwrap_or(0);
        let bn = arr[1].as_object().map(|m| m.len()).unwrap_or(0);
        let cn = arr[2].as_object().map(|m| m.len()).unwrap_or(0);
        let key = (an.min(bn), an.max(bn), cn);
        *circom_hist.entry(key).or_insert(0) += 1;
    }
    let circom_total: usize = circom_hist.values().sum();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256compression_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Sha256compression compile failed: {e}"));
    // Sha256compression() takes no template parameters.
    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_opt = rc.cs.num_constraints();
    let _ = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();

    let mut ach_hist: BTreeMap<ShapeKey, usize> = BTreeMap::new();
    for c in rc.cs.constraints() {
        let a = c.a.simplify();
        let b = c.b.simplify();
        let cc = c.c.simplify();
        let an = a.terms().len();
        let bn = b.terms().len();
        let cn = cc.terms().len();
        let key = (an.min(bn), an.max(bn), cn);
        *ach_hist.entry(key).or_insert(0) += 1;
    }

    let mut all_keys: BTreeSet<ShapeKey> = BTreeSet::new();
    all_keys.extend(circom_hist.keys().copied());
    all_keys.extend(ach_hist.keys().copied());
    let mut rows: Vec<DiffRow> = all_keys
        .iter()
        .map(|&k| {
            let cir = *circom_hist.get(&k).unwrap_or(&0);
            let ach = *ach_hist.get(&k).unwrap_or(&0);
            (k, cir, ach, ach as i64 - cir as i64)
        })
        .collect();
    rows.sort_by(|x, y| y.3.abs().cmp(&x.3.abs()).then(x.0.cmp(&y.0)));

    eprintln!("\n=== Sha256compression(1) standalone — achronyme post-O1 vs circom --O2 ===");
    eprintln!("achronyme pre-opt    = {pre_opt}");
    eprintln!("achronyme post-O1    = {post_o1}");
    eprintln!("circom    --O2       = {circom_total}");
    eprintln!(
        "per-block residual   = {:+} c   (achronyme - circom)",
        post_o1 as i64 - circom_total as i64
    );
    eprintln!();
    eprintln!("=== Reference: full SHA-256(64) residual = +112 c ===");
    eprintln!("If per-block residual matches +112, the gap is in Sha256compression itself.");
    eprintln!(
        "If per-block residual is 0, the gap is in the outer Sha256 wrapper (padding/length/output)."
    );
    eprintln!("If per-block residual is < 0, the wrapper-only delta = +112 - (per-block) c.");
    eprintln!();
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "(min,max,|C|)", "circomO2", "achO1", "delta(ach-cir)"
    );
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "-------------", "--------", "-----", "--------------"
    );
    for (k, cir, ach, delta) in rows.iter().take(25) {
        eprintln!(
            "  ({:>2},{:>2},{:>2})    {:>12} {:>10} {:>+15}",
            k.0, k.1, k.2, cir, ach, delta
        );
    }
}

/// Cluster size diagnostic: for each circomlib template, build the
/// raw R1CS, partition the linear constraints by shared signal, and
/// dump the cluster size histogram. Validates whether
/// `CLUSTER_FALLBACK_THRESHOLD = 500` actually matters in practice
/// (i.e. there exist clusters in the (500, 5000) range that get
/// routed to the greedy fallback).
///
/// Stays `#[ignore]`d so it does not run in the default test pass;
/// invoke with `--ignored cluster_size_diagnostic -- --nocapture`.
#[test]
#[ignore = "Diagnostic-only: run with --ignored cluster_size_diagnostic -- --nocapture to inspect cluster size distributions per circuit."]
fn cluster_size_diagnostic() {
    use std::collections::{BTreeMap, HashSet};

    fn compile(name: &str, file: &str, inputs: HashMap<String, FieldElement<Bn254Fr>>) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(file);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];

        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("compile {name} failed: {e}"));
        let prove_ir = &compile_result.prove_ir;
        let capture_values = &compile_result.capture_values;
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();

        let mut program = prove_ir
            .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
            .unwrap_or_else(|e| panic!("instantiate {name} failed: {e}"));
        ir::passes::optimize(&mut program);

        let mut all_signals =
            circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
                .unwrap_or_else(|e| panic!("witness {name} failed: {e}"));
        for (cname, fe) in &fe_captures {
            all_signals.entry(cname.clone()).or_insert(*fe);
        }

        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler
            .compile_ir_with_witness(&program, &all_signals)
            .unwrap_or_else(|e| panic!("r1cs {name} failed: {e}"));

        // Re-implement the clustering logic here (build_clusters_by_signal
        // is pub(super), not exposed) to inspect raw cluster sizes
        // before any optimization.
        let raw = compiler.cs.constraints();
        let num_pub_inputs = compiler.cs.num_pub_inputs();
        let protected: HashSet<usize> = (0..=num_pub_inputs).collect();

        // Walk linear constraints, build first-owner Union-Find by signal.
        // Same logic as build_clusters_by_signal.
        let mut linear_indices: Vec<usize> = Vec::new();
        for (i, c) in raw.iter().enumerate() {
            let a = c.a.simplify();
            let b = c.b.simplify();
            let a_const = a.is_constant();
            let b_const = b.is_constant();
            if a_const || b_const {
                linear_indices.push(i);
            }
        }
        let n = linear_indices.len();
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(parent: &mut [usize], mut x: usize) -> usize {
            let mut r = x;
            while parent[r] != r {
                r = parent[r];
            }
            while parent[x] != r {
                let n = parent[x];
                parent[x] = r;
                x = n;
            }
            r
        }
        let mut first_owner: HashMap<usize, usize> = HashMap::new();
        for (loc_idx, &orig_idx) in linear_indices.iter().enumerate() {
            let c = &raw[orig_idx];
            for lc in [&c.a, &c.b, &c.c] {
                for (var, _) in lc.terms() {
                    let sig = var.index();
                    if sig == 0 || protected.contains(&sig) {
                        continue;
                    }
                    match first_owner.get(&sig) {
                        Some(&owner) => {
                            let ra = find(&mut parent, loc_idx);
                            let rb = find(&mut parent, owner);
                            if ra != rb {
                                parent[ra] = rb;
                            }
                        }
                        None => {
                            first_owner.insert(sig, loc_idx);
                        }
                    }
                }
            }
        }
        let mut buckets: HashMap<usize, usize> = HashMap::new();
        for i in 0..n {
            *buckets.entry(find(&mut parent, i)).or_insert(0) += 1;
        }
        let mut sizes: Vec<usize> = buckets.values().copied().collect();
        sizes.sort_unstable();

        let total_linear = n;
        let max_size = sizes.last().copied().unwrap_or(0);
        let n_clusters = sizes.len();

        // Bucket counts for histogram thresholds.
        let mut histo: BTreeMap<&str, usize> = BTreeMap::new();
        for &s in &sizes {
            let bucket = match s {
                1 => "1",
                2..=10 => "2-10",
                11..=100 => "11-100",
                101..=350 => "101-350",
                351..=500 => "351-500",
                501..=1_000 => "501-1000",
                1_001..=5_000 => "1001-5000",
                _ => "5000+",
            };
            *histo.entry(bucket).or_insert(0) += 1;
        }

        let raw_total = raw.len();
        eprintln!("\n[{name}]");
        eprintln!(
            "  raw constraints = {raw_total}, linear = {total_linear}, clusters = {n_clusters}, max cluster = {max_size}"
        );
        eprintln!("  cluster size histogram:");
        for (bucket, count) in &histo {
            eprintln!("    {bucket:>10} : {count}");
        }
    }

    fn fe(v: u64) -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_u64(v)
    }
    let one = |k: &str, v: u64| -> HashMap<String, FieldElement<Bn254Fr>> {
        std::iter::once((k.to_string(), fe(v))).collect()
    };

    compile(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        one("in", 13),
    );
    compile("IsZero", "test/circom/iszero.circom", one("in", 0));
    compile(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        [("in_0", fe(3)), ("in_1", fe(10))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        (0..8).map(|i| (format!("in_{i}"), fe(i % 2))).collect(),
    );
    compile(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        (0..253).map(|i| (format!("e_{i}"), fe(0))).collect(),
    );
    let mut ema_inputs: HashMap<String, FieldElement<Bn254Fr>> =
        (0..254).map(|i| (format!("e_{i}"), fe(0))).collect();
    ema_inputs.insert("p_0".to_string(), fe(0));
    ema_inputs.insert("p_1".to_string(), fe(1));
    compile(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        ema_inputs,
    );
    compile(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        [("inputs_0", fe(1)), ("inputs_1", fe(2))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        [("ins_0", fe(1)), ("ins_1", fe(2)), ("k", fe(0))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
}

// circomlib's bigint-emulation templates (BigMultNoCarry,
// BigMultShortLong, BigSub, etc.) use template-local `var` arrays as
// symbolic accumulators for the polynomial-fingerprint witness-hint
// pattern. Each accumulator slot holds a CircuitExpr built up via
// indexed `=` reset and compound `+=` writes in nested loops; the
// per-slot SSA-shadow lowering rebinds the flat element under
// `<base>_<flat>` so the later `out[i] <-- prod_val[i]` and
// `out_poly[i] === a_poly[i] * b_poly[i]` constraint emissions read
// the correct accumulated value.

/// Positive: zero-init then read back a 1D var-array slot.
///
/// Smallest unit that exercises:
/// 1. `var X[N];` with no init materialising N zero Lets.
/// 2. `X[i] = 0;` re-binding the slot under the const-folded iter
///    index via SSA shadow.
/// 3. `out[i] <-- X[i];` reading the slot back through
///    `env.resolve_array_element` and emitting a witness hint.
#[test]
fn var_array_indexed_assign_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal output out[n];
            var acc[n];
            for (var i = 0; i < n; i++) {
                acc[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                out[i] <-- acc[i];
                out[i] === a[i];
            }
        }
        component main = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_smoke.circom");
    std::fs::write(&tmp, src).unwrap();
    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    assert!(
        result.prove_ir.body.len() >= 3,
        "expected at least 3 nodes (zero-init Lets), got {}",
        result.prove_ir.body.len()
    );
}

/// Positive: compound `+=` writes to a 1D var-array slot accumulate
/// signal-arithmetic, exercising the polynomial-fingerprint shape
/// (`prod_val[i+j] += a[i] * b[j]`) on the smallest possible body.
#[test]
fn var_array_compound_add_accumulator_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal input b[n];
            signal output out[2 * n - 1];
            var prod_val[2 * n - 1];
            for (var i = 0; i < 2 * n - 1; i++) {
                prod_val[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                for (var j = 0; j < n; j++) {
                    prod_val[i + j] += a[i] * b[j];
                }
            }
            for (var i = 0; i < 2 * n - 1; i++) {
                out[i] <-- prod_val[i];
                out[i] === prod_val[i];
            }
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_accumulator.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive: 2D var-array allocation + per-slot writes through
/// `env.strides`. Mirrors the `var split[k][3];` shape in
/// `BigMultShortLong`.
#[test]
fn var_array_2d_indexed_assign_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal output out[n];
            var grid[2][3];
            for (var i = 0; i < 2; i++) {
                for (var j = 0; j < 3; j++) {
                    grid[i][j] = 0;
                }
            }
            for (var i = 0; i < n; i++) {
                grid[0][i] += a[i];
                out[i] <-- grid[0][i];
                out[i] === grid[0][i];
            }
        }
        component main = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_2d.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Adversarial: a non-const dimension on a var-array declaration must
/// fail loudly rather than silently producing a zero-length array.
#[test]
fn var_array_non_const_dim_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T() {
            signal input n;
            var arr[n];
            arr[0] = 0;
        }
        component main = T();
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_nonconst_dim.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on non-const dim, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("var array dimension must be a compile-time constant"),
        "unexpected error: {msg}"
    );
}

/// Adversarial: an out-of-bounds indexed write must fail loudly rather
/// than materialising an unbacked slot.
#[test]
fn var_array_out_of_bounds_write_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T() {
            signal output out;
            var arr[4];
            arr[5] = 0;
            out <-- arr[0];
            out === 0;
        }
        component main = T();
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_oob.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on OOB write, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("out of bounds"), "unexpected error: {msg}");
}

/// Positive math: polynomial accumulator round-trip. Verifies that the
/// SSA-shadow chain materialises the correct CircuitExpr per slot —
/// not just that the compile succeeds. Computes a polynomial product
/// `out[k] = Σ_{i+j=k} a[i] * b[j]` for `n = 2` over the inputs
/// a = [2, 3], b = [5, 7]; expected outputs `[10, 29, 21]`. The R1CS
/// verifier asserts every emitted constraint holds against the provided
/// witness, so a wrong accumulation (stale binding, off-by-one flat
/// index) would fail here rather than slip through the compile-only
/// smoke tests.
#[test]
fn var_array_accumulator_witness_verify() {
    let src = r#"
        pragma circom 2.0.0;
        template Poly2(n) {
            signal input a[n];
            signal input b[n];
            signal output out[2 * n - 1];
            var prod_val[2 * n - 1];
            for (var i = 0; i < 2 * n - 1; i++) {
                prod_val[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                for (var j = 0; j < n; j++) {
                    prod_val[i + j] += a[i] * b[j];
                }
            }
            for (var i = 0; i < 2 * n - 1; i++) {
                out[i] <== prod_val[i];
            }
        }
        component main {public [a, b]} = Poly2(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_witness.circom");
    std::fs::write(&tmp, src).unwrap();

    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a_0".into(), FieldElement::<Bn254Fr>::from_u64(2));
    inputs.insert("a_1".into(), FieldElement::<Bn254Fr>::from_u64(3));
    inputs.insert("b_0".into(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("b_1".into(), FieldElement::<Bn254Fr>::from_u64(7));

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // Math sanity: assert the witness-hint pass actually computed the
    // expected polynomial values before handing them to R1CS.
    let expected = [
        ("out_0", 10u64), // a[0]*b[0]
        ("out_1", 29),    // a[0]*b[1] + a[1]*b[0]
        ("out_2", 21),    // a[1]*b[1]
    ];
    for (name, want) in expected {
        let got = all_signals
            .get(name)
            .unwrap_or_else(|| panic!("witness missing signal `{name}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(want),
            "polynomial slot `{name}`: expected {want}, got {got:?} — \
             SSA-shadow chain produced wrong accumulator value"
        );
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS compile-with-witness failed: {e}"));
    rc.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));
}

/// Adversarial: shadowing a signal output (or any signal-array local)
/// with a `var X[N];` must be rejected. Without the shadow check the
/// zero-init Lets would mask the signal's slot bindings and produce
/// wrong constraints.
#[test]
fn var_array_shadows_signal_output_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal output out[n];
            var out[n];
            out[0] = 0;
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_shadow_signal.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shadowing signal output, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("shadows an existing signal"),
        "unexpected error: {msg}"
    );
}

/// Adversarial: shadowing a template input with a `var` array of the
/// same name must be rejected so reads after the decl stay unambiguous.
#[test]
fn var_array_shadows_input_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input arr[n];
            var arr[n];
            arr[0] = 0;
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_shadow_input.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shadowing input, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("shadows an existing signal"),
        "unexpected error: {msg}"
    );
}

// circomlib bigint emulation declares working buffers via the shape
// `var X[R][C] = call(signal_array, …);` where `call` lifts to Artik
// (`long_div`, `secp256k1_addunequal_func`, `secp256k1_double_func`,
// …) and returns a 2D var array. The lift flattens the return into a
// 1D `LetArray` of `R*C` slots, so without the dimension-aware
// stride seeding the downstream `X[i][j]` reads either fold to the
// wrong slot (stride=1 default) or surface E213 against the R1″
// memoization placeholder when the outer index is the loop variable.

/// Positive: 2D var assigned from an Artik-lifted call has its
/// declared `[R][C]` strides registered. `X[i][j]` reads inside a
/// memoizable loop linearise to `i * C + j` instead of fingering a
/// non-existent flat slot.
#[test]
fn multidim_var_from_call_seeds_strides() {
    let src = r#"
        pragma circom 2.0.0;
        function pair(N, a, b) {
            var out[2][N];
            for (var i = 0; i < N; i++) {
                out[0][i] = a[i] + b[i];
                out[1][i] = a[i] - b[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal input b[N];
            signal output sums[N];
            signal output diffs[N];

            var pr[2][N] = pair(N, a, b);
            for (var i = 0; i < N; i++) {
                sums[i]  <-- pr[0][i];
                sums[i]  === pr[0][i];
                diffs[i] <-- pr[1][i];
                diffs[i] === pr[1][i];
            }
        }
        component main {public [a, b]} = T(8);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_strides.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive: a memoizable read loop over a 2D var bound from a call
/// compiles cleanly (the read body crosses the memoize threshold,
/// `end - start >= 4`, so the inner `i` is held as the R1″
/// placeholder). Without the dimension-aware stride seeding, the
/// `pr[0][i]` lowering would surface E213 against the placeholder.
#[test]
fn multidim_var_from_call_memoizable_loop_compiles() {
    let src = r#"
        pragma circom 2.0.0;
        function pair(N, a, b) {
            var out[2][N];
            for (var i = 0; i < N; i++) {
                out[0][i] = a[i] + b[i];
                out[1][i] = a[i] - b[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal input b[N];
            signal output sums[N];
            signal output diffs[N];

            var pr[2][N] = pair(N, a, b);
            for (var i = 0; i < N; i++) {
                sums[i]  <-- pr[0][i];
                sums[i]  === pr[0][i];
                diffs[i] <-- pr[1][i];
                diffs[i] === pr[1][i];
            }
        }
        component main {public [a, b]} = T(8);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_memoizable.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Adversarial: declared multi-dim shape whose cell count disagrees
/// with the initializer's flat length surfaces a clean error, not a
/// silently mis-strided array.
#[test]
fn multidim_var_from_call_dim_mismatch_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        function pair_len(N, a) {
            var out[N];
            for (var i = 0; i < N; i++) {
                out[i] = a[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal output sums[N];
            // Declared shape [2][N] = 2*N cells, but pair_len returns N.
            var bad[2][N] = pair_len(N, a);
            sums[0] <-- bad[0][0];
            sums[0] === bad[0][0];
        }
        component main {public [a]} = T(4);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_mismatch.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shape mismatch, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("declared shape") && msg.contains("but the initializer produced"),
        "unexpected error: {msg}"
    );
}

// `for (var i = 0; i <= k; i++)` with `k` a template parameter
// appears across circomlib's bigint emulation as the canonical
// k+1-iteration range-check loop (`Num2Bits(n)` per quotient
// register, etc.). The classifier rewrites the inclusive form to
// `i < k + 1` via `LoopBound::Expr`; the downstream witness +
// instantiation path evaluates the expression against the bound
// capture values.

/// Positive: `i <= k` over a template parameter compiles and
/// emits the correct iteration count. The k+1-sized output array
/// is fully written.
#[test]
fn loop_inclusive_bound_capture_compiles() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a[k + 1];
            signal output out[k + 1];
            for (var i = 0; i <= k; i++) {
                out[i] <== a[i];
            }
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_le_capture_smoke.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive math: the k+1-th iteration actually runs. Wires
/// distinguishable values per slot and R1CS-verifies the resulting
/// constraints — a wrong iteration count (e.g. off-by-one from a
/// stale `i < k` rewrite) would leave `out_k` unconstrained.
#[test]
fn loop_inclusive_bound_capture_witness_verify() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a[k + 1];
            signal output out[k + 1];
            for (var i = 0; i <= k; i++) {
                out[i] <== a[i];
            }
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_le_capture_witness.circom");
    std::fs::write(&tmp, src).unwrap();

    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for i in 0..4u64 {
        inputs.insert(format!("a_{i}"), FieldElement::<Bn254Fr>::from_u64(100 + i));
    }

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // The k+1-th slot (`out_3`, since k=3) must be written; a stale
    // `i < k` rewrite would leave it absent from the witness.
    for i in 0..4u64 {
        let got = all_signals
            .get(&format!("out_{i}"))
            .unwrap_or_else(|| panic!("witness missing signal `out_{i}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(100 + i),
            "out_{i}: expected {}, got {got:?}",
            100 + i,
        );
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS compile-with-witness failed: {e}"));
    rc.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));
}

/// Adversarial: `i >= k` (ascending step) is still not a recognised
/// loop shape — only the descending family `i >= 0` / `i != -1` is
/// supported, and only the inclusive-upper-bound family widens to
/// include captures via this change. A stray `i >= k` with `i++`
/// would produce an infinite range if accepted naively.
#[test]
fn loop_ascending_ge_capture_still_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a;
            signal output out;
            var acc = 0;
            for (var i = 0; i >= k; i++) {
                acc = acc + 1;
            }
            out <== a + acc;
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_ge_capture_rejected.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on ascending i >= k, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("for loop condition must be"),
        "unexpected error: {msg}"
    );
}

// ── R1CS optimization diagnostic ─────────────────────────────────

/// Diagnostic: dump all constraints for Num2Bits(8) before and after
/// optimization to verify soundness.
#[test]
fn num2bits_optimization_diagnostic() {
    use constraints::r1cs::Variable;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/num2bits_8.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs).unwrap();
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap();
    ir::passes::optimize(&mut program);

    // Print IR instructions to understand wire names
    eprintln!("\n=== IR Instructions ===");
    for (i, inst) in program.iter().enumerate() {
        eprintln!("  [{i:3}] {inst}");
    }

    let inputs: HashMap<String, FieldElement<Bn254Fr>> = [("in", 13u64)]
        .iter()
        .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let mut witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap();

    // Print constraints BEFORE optimization
    eprintln!(
        "\n=== Constraints BEFORE optimization ({}) ===",
        compiler.cs.num_constraints()
    );
    for (i, c) in compiler.cs.constraints().iter().enumerate() {
        let a_val = c.a.evaluate(&witness).unwrap();
        let b_val = c.b.evaluate(&witness).unwrap();
        let c_val = c.c.evaluate(&witness).unwrap();

        let fmt_lc = |lc: &constraints::LinearCombination| -> String {
            let simplified = lc.simplify();
            if simplified.terms().is_empty() {
                return "0".to_string();
            }
            simplified
                .terms()
                .iter()
                .map(|(v, coeff)| {
                    let coeff_u64 = coeff.to_canonical()[0];
                    if *v == Variable::ONE {
                        format!("{coeff_u64}")
                    } else if coeff_u64 == 1 {
                        format!("w{}", v.index())
                    } else {
                        format!("{coeff_u64}·w{}", v.index())
                    }
                })
                .collect::<Vec<_>>()
                .join(" + ")
        };

        eprintln!(
            "  [{i:2}] ({}) * ({}) = ({})   | A={}, B={}, C={}",
            fmt_lc(&c.a),
            fmt_lc(&c.b),
            fmt_lc(&c.c),
            a_val.to_canonical()[0],
            b_val.to_canonical()[0],
            c_val.to_canonical()[0],
        );
    }

    // Print which variables are public
    eprintln!("\n=== Variable layout ===");
    eprintln!(
        "  Public inputs: {} (indices 1..={})",
        compiler.cs.num_pub_inputs(),
        compiler.cs.num_pub_inputs()
    );
    eprintln!("  Total variables: {}", compiler.cs.num_variables());
    for (name, var) in &compiler.bindings {
        eprintln!(
            "  w{} = {name} = {}",
            var.index(),
            witness[var.index()].to_canonical()[0]
        );
    }

    // Optimize
    let stats = compiler.optimize_r1cs();
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }

    // Print what was substituted
    eprintln!(
        "\n=== Substitutions ({} variables eliminated) ===",
        stats.variables_eliminated
    );
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            let fmt_lc = |lc: &constraints::LinearCombination| -> String {
                let simplified = lc.simplify();
                if simplified.terms().is_empty() {
                    return "0".to_string();
                }
                simplified
                    .terms()
                    .iter()
                    .map(|(v, coeff)| {
                        let coeff_u64 = coeff.to_canonical()[0];
                        if *v == Variable::ONE {
                            format!("{coeff_u64}")
                        } else if coeff_u64 == 1 {
                            format!("w{}", v.index())
                        } else {
                            format!("{coeff_u64}·w{}", v.index())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" + ")
            };
            eprintln!("  w{var_idx} → {}", fmt_lc(lc));
        }
    }

    // Print constraints AFTER optimization
    eprintln!(
        "\n=== Constraints AFTER optimization ({}) ===",
        compiler.cs.num_constraints()
    );
    for (i, c) in compiler.cs.constraints().iter().enumerate() {
        let a_val = c.a.evaluate(&witness).unwrap();
        let b_val = c.b.evaluate(&witness).unwrap();
        let c_val = c.c.evaluate(&witness).unwrap();

        let fmt_lc = |lc: &constraints::LinearCombination| -> String {
            let simplified = lc.simplify();
            if simplified.terms().is_empty() {
                return "0".to_string();
            }
            simplified
                .terms()
                .iter()
                .map(|(v, coeff)| {
                    let coeff_u64 = coeff.to_canonical()[0];
                    if *v == Variable::ONE {
                        format!("{coeff_u64}")
                    } else if coeff_u64 == 1 {
                        format!("w{}", v.index())
                    } else {
                        format!("{coeff_u64}·w{}", v.index())
                    }
                })
                .collect::<Vec<_>>()
                .join(" + ")
        };

        eprintln!(
            "  [{i:2}] ({}) * ({}) = ({})   | A·B={}, C={}",
            fmt_lc(&c.a),
            fmt_lc(&c.b),
            fmt_lc(&c.c),
            a_val.mul(&b_val).to_canonical()[0],
            c_val.to_canonical()[0],
        );
    }

    // Verify
    compiler.cs.verify(&witness).unwrap();
    eprintln!("\n  ✓ Optimized system VERIFIED with witness (in=13)");
}

// ── R1CS optimization benchmark ──────────────────────────────────

/// Benchmark: compare constraint counts before/after R1CS linear
/// constraint elimination for key circomlib circuits.
///
/// The `cirO0` / `cirO1` / `cirO2` columns are measured directly against
/// `circom` 2.2.3 (`circom --r1cs --Ox -l test/circomlib`) and reported
/// as **total constraints (non-linear + linear)**, matching the semantics
/// of `R1CSCompiler::cs::num_constraints()`. Re-measure these literals
/// whenever the upstream `circom` baseline shifts; stale values silently
/// distort the achronyme-vs-circom narrative.
#[test]
fn r1cs_optimization_benchmark() {
    /// Compile a circom circuit and return constraint counts at three
    /// optimisation levels:
    /// - `before_opt`  -- raw R1CS output, no optimization.
    /// - `after_o1`    -- after `optimize_r1cs()` (O1 linear elimination).
    /// - `after_o2_s`  -- after `optimize_r1cs_o2_sparse()` (sparse DEDUCE).
    ///
    /// The sparse path is measured on a clone of the pre-opt constraint
    /// vec so the live R1CSCompiler keeps its O1-substitution map for
    /// witness verification.
    fn compile_and_measure(
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
    fn compile_and_measure_witnessless(name: &str, circom_file: &str) -> (usize, usize, usize) {
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

    eprintln!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║            R1CS Constraint Benchmark: achronyme vs circom               ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ {:26} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7} ║",
        "Circuit", "achO0", "achO1", "cirO0", "cirO1", "cirO2", "Elim", "Time"
    );
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");

    /// Format and print a benchmark row.
    fn print_row(
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

    let t0 = std::time::Instant::now();

    // Collected (name, achO1, achO2-sparse, circom-O2-baseline-str) per
    // circuit. Printed in the second comparison table after the main
    // achronyme-vs-circom view -- focuses the reader on the hypothesis
    // under test ("does sparse DEDUCE recover constraints we miss with
    // O1 alone?") without breaking the existing column layout.
    let mut sparse_summary: Vec<(&str, usize, usize, &str)> = Vec::new();

    // Num2Bits(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        &[("in", 13)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Num2Bits(8)",
        b,
        a,
        "9",
        "9",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Num2Bits(8)", a, asp, "9"));

    // IsZero
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "IsZero",
        "test/circom/iszero.circom",
        &[("in", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "IsZero",
        b,
        a,
        "2",
        "2",
        "2",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("IsZero", a, asp, "2"));

    // LessThan(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        &[("in_0", 3), ("in_1", 10)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "LessThan(8)",
        b,
        a,
        "12",
        "12",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("LessThan(8)", a, asp, "9"));

    // Pedersen(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &(0..8)
            .map(|i| (format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(i % 2)))
            .collect(),
    );
    print_row(
        "Pedersen(8)",
        b,
        a,
        "243",
        "95",
        "13",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Pedersen(8)", a, asp, "13"));

    // EscalarMulFix(253)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        &(0..253)
            .map(|i| (format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0)))
            .collect(),
    );
    print_row(
        "EscalarMulFix(253)",
        b,
        a,
        "153",
        "62",
        "11",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulFix(253)", a, asp, "11"));

    // EscalarMulAny(254)
    let t = std::time::Instant::now();
    let mut ema_inputs = HashMap::new();
    for i in 0..254 {
        ema_inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    ema_inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    ema_inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    let (b, a, asp) = compile_and_measure(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        &ema_inputs,
    );
    print_row(
        "EscalarMulAny(254)",
        b,
        a,
        "7907",
        "2312",
        "2310",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulAny(254)", a, asp, "2310"));

    // Poseidon(2)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &[("inputs_0", 1), ("inputs_1", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Poseidon(2)",
        b,
        a,
        "765",
        "517",
        "240",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Poseidon(2)", a, asp, "240"));

    // MiMCSponge(2,220,1)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        &[("ins_0", 1), ("ins_1", 2), ("k", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "MiMCSponge(2,220,1)",
        b,
        a,
        "1767",
        "1321",
        "1320",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("MiMCSponge(2,220,1)", a, asp, "1320"));

    // Point2Bits_Strict (BabyJubjub Edwards point → 256-bit packing)
    // Identity point input — cross-template `proven_boolean` lever
    // surfaces here because Num2Bits feeds CompConstant + AliasCheck
    // chain in a single template, a pattern not present in the eight
    // legacy circuits above.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Point2Bits_Strict",
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Point2Bits_Strict",
        b,
        a,
        "2838",
        "1301",
        "1293",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Point2Bits_Strict", a, asp, "1293"));

    // Bits2Point_Strict (256-bit packing → BabyJubjub Edwards point)
    // Inputs marked public via `{public [in]}` in the fixture so the
    // `in[254] === 0` and `signCalc.out === in[255]` constraints
    // survive optimisation rather than being lawfully substituted away.
    let t = std::time::Instant::now();
    let mut b2p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    b2p_inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    for i in 1..256 {
        b2p_inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    let (b, a, asp) = compile_and_measure(
        "Bits2Point_Strict",
        "test/circomlib/bits2point_test.circom",
        &b2p_inputs,
    );
    print_row(
        "Bits2Point_Strict",
        b,
        a,
        "2589",
        "1050",
        "1043",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Bits2Point_Strict", a, asp, "1043"));

    // Sha256_2 (2 × 216-bit field-element inputs → 216-bit truncated
    // SHA-256 digest). Distinct shape from `Sha256(N)`: hardcoded
    // length encoding + 2× Num2Bits(216) + Bits2Num(216).
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Sha256_2",
        "test/circomlib/sha256_2_test.circom",
        &[("a", 1), ("b", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Sha256_2",
        b,
        a,
        "204462",
        "31699",
        "30134",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Sha256_2", a, asp, "30134"));

    // EdDSAPoseidon (Poseidon-hash variant of the EdDSA verifier).
    // Inherits the Pointbits cross-template advantage via its single
    // internal `Point2Bits_Strict` invocation on the hash output.
    let t = std::time::Instant::now();
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut eddsa_p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    eddsa_p_inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    eddsa_p_inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    eddsa_p_inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));
    let (b, a, asp) = compile_and_measure(
        "EdDSAPoseidon",
        "test/circomlib/eddsaposeidon_test.circom",
        &eddsa_p_inputs,
    );
    print_row(
        "EdDSAPoseidon",
        b,
        a,
        "21254",
        "8086",
        "4217",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAPoseidon", a, asp, "4217"));

    // EdDSAVerifier(1) — Pedersen-hash variant. No `enabled` escape,
    // verifier always asserts a valid signature, so the benchmark
    // measures constraint shape via the witness-less path. Inherits
    // the Pointbits advantage 3× over (2× Bits2Point_Strict + 1×
    // Point2Bits_Strict in the verifier body).
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("EdDSAVerifier(1)", "test/circomlib/eddsa_test.circom");
    print_row(
        "EdDSAVerifier(1)",
        b,
        a,
        "42919",
        "16498",
        "7417",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAVerifier(1)", a, asp, "7417"));

    // Tornado Cash Withdraw(20) — vendored from tornadocash/tornado-core,
    // ported to circom 2.0. Tree depth 20 (mainnet). Body: 2× Pedersen +
    // 2× Num2Bits(248) + 20× MiMCSponge + 20× DualMux + 4 binding
    // squares. Witness-less because constructing a valid Pedersen-MiMC
    // merkle proof witness requires running the deposit ceremony off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure_witnessless(
        "Tornado Withdraw(20)",
        "test/circomlib/tornado_test.circom",
    );
    print_row(
        "Tornado Withdraw(20)",
        b,
        a,
        "59009",
        "36451",
        "28275",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Tornado Withdraw(20)", a, asp, "28275"));

    // Semaphore(32) — semaphore-protocol/semaphore v4 main circuit.
    // Body: LessThan(251) + BabyPbk + 2× Poseidon(2) +
    // BinaryMerkleRoot(32) (32× Poseidon(2) inside). Witness-less
    // because constructing a valid (secret, merkle proof) pair requires
    // the Semaphore identity setup off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("Semaphore(32)", "test/circomlib/semaphore_test.circom");
    print_row(
        "Semaphore(32)",
        b,
        a,
        "37044",
        "22216",
        "9383",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Semaphore(32)", a, asp, "9383"));

    // Poseidon arity sweep (t = 3, 4, 8, 16). The existing benchmark
    // already covers t=2; this sweep tests how the optimiser scales
    // with the t×t MDS-matrix multiplication and the
    // `(t * nRoundsF + nRoundsP)`-element round-constant vector at
    // wider hashes. Witness uses small consecutive integers.
    for t in [3usize, 4, 8, 16] {
        let label = format!("Poseidon({t})");
        let circ = format!("test/circomlib/poseidon_{t}_test.circom");
        let inputs: HashMap<String, FieldElement<Bn254Fr>> = (0..t)
            .map(|i| {
                (
                    format!("inputs_{i}"),
                    FieldElement::<Bn254Fr>::from_u64((i as u64) + 1),
                )
            })
            .collect();
        let t_w = std::time::Instant::now();
        let (b, a, asp) = compile_and_measure(&label, &circ, &inputs);
        let (cir_o0, cir_o1, cir_o2) = match t {
            3 => ("931", "605", "261"),
            4 => ("1163", "736", "297"),
            8 => ("1965", "1171", "402"),
            16 => ("3675", "2092", "609"),
            _ => unreachable!(),
        };
        print_row(
            &label,
            b,
            a,
            cir_o0,
            cir_o1,
            cir_o2,
            t_w.elapsed().as_secs_f64() * 1000.0,
        );
        // Leak the label into a 'static slice via Box::leak so the
        // benchmark summary table can hold a stable &str. Fine in a
        // test run — the leak lives until process exit.
        let label_static: &'static str = Box::leak(label.into_boxed_str());
        sparse_summary.push((label_static, a, asp, cir_o2));
    }

    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ Total achronyme time: {:>5.0}ms {:>42} ║",
        t0.elapsed().as_secs_f64() * 1000.0,
        ""
    );
    eprintln!("╚════════════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Second table: O1 vs O2-sparse vs circom O2.
    //
    // Validates the hypothesis "sparse DEDUCE recovers constraints O1
    // misses, even on circuits where achronyme already matches or beats
    // circom O2". `gain` is achO1 - achO2s (constraints removed by the
    // sparse pass over O1 alone). `delta` is achO2s - cirO2 (positive
    // means achronyme remains behind, negative means we beat circom).
    eprintln!("+--- DEDUCE-sparse vs circom O2 ----------------------------------+");
    eprintln!(
        "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
        "Circuit", "achO1", "achO2s", "cirO2", "delta", "gain"
    );
    eprintln!("+--------------------------+--------+--------+--------+--------+-------+");
    for (name, a_o1, a_o2s, cir_o2_str) in &sparse_summary {
        let cir_o2: i64 = cir_o2_str.parse().unwrap_or(0);
        let delta: i64 = *a_o2s as i64 - cir_o2;
        let gain: i64 = *a_o1 as i64 - *a_o2s as i64;
        eprintln!(
            "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
            name, a_o1, a_o2s, cir_o2_str, delta, gain
        );
    }
    eprintln!("+------------------------------------------------------------------+");
    eprintln!();
}

/// SHA-256(64) witness-equivalence vs the FIPS-180-4 reference (`sha2` crate).
///
/// This is *semantic* verification — does our compile + witness pipeline
/// produce the same 256-bit digest the reference produces? It is
/// orthogonal to constraint-count parity (separate R1CS-optimizer
/// concern). The test runs `compute_witness_hints_with_captures` over
/// the Lysis-frontend ProveIR with concrete bit inputs and reads the
/// 256 `out_i` signals from the env. If any `out_i` is missing or
/// disagrees with `sha2::Sha256::digest`, the test fails.
///
/// Bit ordering follows circomlib convention: `in[byte*8 + bit]` is bit
/// (7-bit) of the input byte, MSB-first. `out[byte*8 + bit]` is bit
/// (7-bit) of the digest byte, MSB-first.
///
/// `#[ignore]`d because compile alone is ~47s on this host. Run
/// explicitly via `cargo test ... --ignored
/// sha256_64_witness_matches_sha2_reference`.
#[test]
#[ignore = "SHA-256(64) witness-equivalence — compile is ~47s on this host. Run with --ignored to verify the achronyme pipeline computes the same digest as FIPS-180-4."]
fn sha256_64_witness_matches_sha2_reference() {
    use sha2::{Digest, Sha256};
    use std::time::Instant;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // Concrete 8-byte input — picked to have varied bits so a missed
    // alias collapse would surface as a digest mismatch.
    let message: [u8; 8] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("  [compile]  {:?}", t0.elapsed());

    // Build inputs: in_{byte*8 + bit} = bit (7-bit) of message[byte], MSB-first.
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (byte_idx, byte) in message.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit_val = ((byte >> (7 - bit_idx)) & 1) as u64;
            inputs.insert(
                format!("in_{}", byte_idx * 8 + bit_idx),
                FieldElement::<Bn254Fr>::from_u64(bit_val),
            );
        }
    }

    let t1 = Instant::now();
    let env = circom::witness::compute_witness_hints_with_captures(
        &compile_result.prove_ir,
        &inputs,
        &compile_result.capture_values,
    )
    .expect("compute_witness_hints_with_captures");
    eprintln!("  [witness]  {:?}  env_size={}", t1.elapsed(), env.len());

    // Reference digest from sha2 crate (FIPS-180-4 bit-exact).
    let expected = Sha256::digest(message);

    // Read 256 output bits and reconstruct 32 bytes MSB-first.
    let mut got = [0u8; 32];
    let mut missing: Vec<usize> = Vec::new();
    for (byte_idx, byte) in got.iter_mut().enumerate() {
        for bit_idx in 0..8 {
            let key = format!("out_{}", byte_idx * 8 + bit_idx);
            match env.get(&key) {
                Some(fe) => {
                    let bit = u8::from(fe == &FieldElement::<Bn254Fr>::one());
                    *byte |= bit << (7 - bit_idx);
                }
                None => missing.push(byte_idx * 8 + bit_idx),
            }
        }
    }

    assert!(
        missing.is_empty(),
        "SHA-256 witness missing {} of 256 output bits — first missing indices: {:?}",
        missing.len(),
        &missing[..missing.len().min(8)]
    );

    assert_eq!(
        &got[..],
        expected.as_slice(),
        "SHA-256(64) digest mismatch:\n  got:      {}\n  expected: {}",
        hex_encode(&got),
        hex_encode(expected.as_slice()),
    );

    eprintln!("  [verified] digest = {}", hex_encode(&got));
}

/// SHA-256(64) full R1CS-verify-with-witness regression.
///
/// Companion to [`sha256_64_witness_matches_sha2_reference`] and
/// [`sha256_64_lysis_hard_gate`]. Those two cover compile budget +
/// witness-vs-FIPS bit-equivalence respectively, but neither runs the
/// IR's `AssertEq` chain against a populated witness — the hard-gate
/// stops at constraint counting and the witness-equivalence test reads
/// the bit outputs directly out of `compute_witness_hints` (Lysis VM
/// hints) without re-checking that those values satisfy every R1CS
/// constraint produced from the compiled IR.
///
/// That coverage shape can hide regressions where the IR emits
/// constraints that count correctly and produce a satisfying-looking
/// witness on the hint side, yet collapse multiple iter-distinct
/// `AssertEq`s onto a single shared RHS so witness eval rejects the
/// program. This test plugs the gap by running
/// `compile_ir_with_witness` + `cs.verify` on a fixed 8-byte input —
/// any future spill / dataflow regression that produces witness-
/// incompatible constraints surfaces here even when the constraint
/// count stays within the hard-gate's tolerance.
///
/// `#[ignore]`d because the SHA-256(64) compile path is ~13 s on this
/// host. Run with `--ignored sha256_64_r1cs_verify_with_witness`
/// before pushing changes that touch the Walker, instantiate, or
/// witness-hint paths.
#[test]
#[ignore = "SHA-256(64) full R1CS-verify-with-witness regression — compile is ~13s on this host. Run with --ignored before pushing changes that touch the Lysis walker, instantiate, witness, or R1CS pipelines."]
fn sha256_64_r1cs_verify_with_witness() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let message: [u8; 8] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    for (byte_idx, byte) in message.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit_val = u64::from((byte >> (7 - bit_idx)) & 1);
            inputs.insert(
                format!("in_{}", byte_idx * 8 + bit_idx),
                FieldElement::<Bn254Fr>::from_u64(bit_val),
            );
        }
    }

    let n = circomlib_e2e_verify_fe("SHA-256(64)", "test/circomlib/sha256_test.circom", &inputs);
    assert!(n > 0, "SHA-256(64) must produce non-empty constraint set");
}

/// Sha256_2: 2-input SHA-256 variant (a, b ∈ [0, 2^216)).
///
/// Distinct shape from the parametric `Sha256(N)` already covered by
/// `sha256_64_*` tests:
///   - Hardcoded length encoding via raw `inp[i] <== const` (vs. a
///     parametric padding loop).
///   - Two `Num2Bits(216)` decompositions (216-bit inputs are an
///     unusual size — most templates use 32, 64, or 254).
///   - `Sha256compression` invoked directly without the `Sha256(N)`
///     wrapper.
///
/// Smoke test: compile + instantiate + R1CS-build + verify on small
/// constants. Surfaces any frame-overflow, instantiation amplification,
/// or witness-vs-IR drift specific to this template shape.
#[test]
#[ignore = "Sha256_2 compile + instantiate + R1CS — heavy (single Sha256compression dominates). Run with --ignored sha256_2_real_circomlib."]
fn sha256_2_real_circomlib() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(2));

    let n = circomlib_e2e_optimized("Sha256_2", "test/circomlib/sha256_2_test.circom", &inputs);
    assert!(n > 0, "Sha256_2 must produce non-empty constraint set");
}
