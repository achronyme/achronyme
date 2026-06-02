use super::*;

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
