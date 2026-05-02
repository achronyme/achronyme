//! HARD GATE — per-instruction hash-consing must shrink a
//! SHA-256(64)-shaped skeleton by at least 10× on the pure channel
//! (RFC §11.2). Failure here invalidates the hash-consing premise.
//!
//! ## What the skeleton is (and isn't)
//!
//! It is a **structural shape** — 64 unrolled "round bodies" each
//! emitting ~20 pure arithmetic ops over a small shared-operand
//! pool, plus one side-effect per round (an `AssertEq`).
//!
//! It is **not** a semantically-faithful SHA-256: the σ/Σ
//! functions are not the real rotates+XOR, the message schedule
//! does not evolve, and the constants `K[i]` are absent. The only
//! property we exercise here is per-instruction interning: when the
//! same `(opcode, operand_ids)` shape is emitted N times through
//! the executor, the interner must collapse it to one node.
//!
//! The real SHA-256 "at scale" OOM fix relies on template-body
//! lifting to dedup *across varying operands*; this skeleton is
//! the precondition that lifting then builds on top of.
//!
//! ## The gate
//!
//! With a program that emits `R` rounds × `P` pure ops each, plus a
//! constant operand pool of size `K`, running through the full
//! `encode → decode → validate → execute` pipeline:
//!
//! - `StubSink` records ~`K + R·P` pure entries (no dedup).
//! - `InterningSink` records ~`K + P` pure entries (full dedup).
//!
//! Reduction ratio ~= `(K + R·P) / (K + P)`, which for `R = 64`,
//! `P = 20`, `K = 2` is ~58×. The gate asserts ≥10×.

use lysis::{
    bytecode::validate, decode, encode, execute, InterningSink, LysisConfig, Program,
    ProgramBuilder, StubSink,
};
use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

fn fe(x: u64) -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([x, 0, 0, 0])
}

/// Build a 64-round SHA-256-shaped skeleton.
///
/// Register layout per round:
///   r0 — `state` (shared across all rounds).
///   r1 — `k_pool` (shared constant).
///   r2..r21 — 20 pure-op scratch slots that each round rewrites.
///
/// Every round re-emits the same 20 `(opcode, operands)` shapes
/// using r0 / r1 as inputs. `InterningSink` collapses the 20 shapes
/// to 20 unique pure nodes for the whole program; `StubSink` keeps
/// `20 × R` entries. Per-round `AssertEq(r0, r1)` is a side-effect
/// that survives intact in both sinks (RFC §5.3).
fn build_sha256_64_skeleton(rounds: usize) -> Program<Bn254Fr> {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    b.intern_field(fe(1));
    b.intern_field(fe(0x428a_2f98)); // K[0] flavor, a single fixed value

    // r0 = state; r1 = k_pool. Both loaded once up front.
    b.load_const(0, 0).load_const(1, 1);

    // 20 pure-op patterns over (r0, r1). Each produces a distinct
    // result register so register allocation doesn't conflict, but
    // the *structural* shape is identical across rounds.
    for _ in 0..rounds {
        b.emit_add(2, 0, 1) //  1
            .emit_mul(3, 0, 1) //  2
            .emit_add(4, 2, 3) //  3
            .emit_mul(5, 4, 4) //  4
            .emit_add(6, 5, 0) //  5
            .emit_mul(7, 6, 1) //  6
            .emit_sub(8, 6, 7) //  7
            .emit_neg(9, 8) //  8
            .emit_mul(10, 9, 9) //  9
            .emit_add(11, 10, 5) // 10
            .emit_sub(12, 11, 3) // 11
            .emit_is_eq(13, 0, 1) // 12
            .emit_is_lt(14, 0, 1) // 13
            .emit_mux(15, 13, 11, 12) // 14
            .emit_add(16, 15, 10) // 15
            .emit_mul(17, 16, 16) // 16
            .emit_neg(18, 17) // 17
            .emit_add(19, 18, 4) // 18
            .emit_mul(20, 19, 19) // 19
            .emit_sub(21, 20, 0) // 20
            // Side-effect per round: keeps R entries in the effect channel
            // on InterningSink and R entries overall on StubSink.
            .emit_assert_eq(0, 1);
    }
    b.halt();
    b.finish()
}

fn pipeline_with_stub(program: &Program<Bn254Fr>) -> (usize, usize) {
    let bytes = encode(program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).expect("execute");
    // StubSink doesn't separate pure / effect — everything is in
    // one Vec. Count by variant.
    let flat = sink.into_instructions();
    let effects = flat.iter().filter(|i| i.is_side_effect()).count();
    (flat.len() - effects, effects)
}

fn pipeline_with_intern(program: &Program<Bn254Fr>) -> (usize, usize) {
    let bytes = encode(program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).expect("execute");
    (sink.pure_len(), sink.effect_len())
}

// ------------------------------------------------------------------
// HARD GATE
// ------------------------------------------------------------------

#[test]
fn hard_gate_pure_channel_reduction_at_least_10x() {
    const ROUNDS: usize = 64;
    const PURE_OPS_PER_ROUND: usize = 20;

    let program = build_sha256_64_skeleton(ROUNDS);

    let (stub_pure, stub_effects) = pipeline_with_stub(&program);
    let (intern_pure, intern_effects) = pipeline_with_intern(&program);

    eprintln!("SHA-256(64) skeleton — {ROUNDS} rounds × {PURE_OPS_PER_ROUND} pure ops:");
    eprintln!("  StubSink:       pure = {stub_pure:>5}  effects = {stub_effects:>3}");
    eprintln!("  InterningSink:  pure = {intern_pure:>5}  effects = {intern_effects:>3}");
    let ratio = stub_pure as f64 / intern_pure as f64;
    eprintln!("  Reduction:      {ratio:.1}×");

    // Side-effect channel is never deduped — one AssertEq per round
    // survives in both sinks. Equal counts.
    assert_eq!(stub_effects, ROUNDS);
    assert_eq!(intern_effects, ROUNDS);

    // Pure-channel reduction HARD GATE (RFC §11.2).
    assert!(
        ratio >= 10.0,
        "HARD GATE failed: pure reduction {ratio:.1}× < 10× required"
    );
}

// ------------------------------------------------------------------
// Supporting tests — these keep the invariants honest even if the
// gate is relaxed locally for debugging.
// ------------------------------------------------------------------

#[test]
fn stub_count_scales_linearly_with_rounds() {
    let small = build_sha256_64_skeleton(8);
    let large = build_sha256_64_skeleton(64);
    let (sp, _) = pipeline_with_stub(&small);
    let (lp, _) = pipeline_with_stub(&large);
    // 8× the rounds → roughly 8× the pure count (constants are
    // loaded once up front, so not strictly linear, but close).
    assert!(lp > 7 * (sp - 2)); // subtract the 2 const loads
}

#[test]
fn intern_count_is_flat_across_rounds() {
    // Same structural program with 8 vs 64 rounds produces the
    // SAME pure count under hash-consing — that's the whole point.
    let eight = build_sha256_64_skeleton(8);
    let sixty_four = build_sha256_64_skeleton(64);
    let (p8, _) = pipeline_with_intern(&eight);
    let (p64, _) = pipeline_with_intern(&sixty_four);
    assert_eq!(
        p8, p64,
        "pure node count should be independent of round count under hash-consing"
    );
}

#[test]
fn materialized_output_shrinks_with_intern() {
    // Materialize the intern result and compare length to stub output.
    let program = build_sha256_64_skeleton(64);

    let bytes = encode(&program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    validate(&decoded, &LysisConfig::default()).expect("validate");

    let mut stub = StubSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut stub).expect("execute");
    let stub_flat = stub.into_instructions();

    let mut intern = InterningSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut intern).expect("execute");
    let intern_flat = intern.materialize();

    // Intern materialize ≪ stub: pure dedup kills the multiplicative
    // blowup. Side-effects are equal count.
    assert!(
        intern_flat.len() * 5 < stub_flat.len(),
        "materialize should be >5× smaller; got stub={} intern={}",
        stub_flat.len(),
        intern_flat.len()
    );
}
