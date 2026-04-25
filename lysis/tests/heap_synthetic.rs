//! Phase 4 — synthetic 250-var fixture that exercises the heap path
//! end-to-end (builder → validator → executor) without going through
//! the circom frontend or the lysis_lift walker. Decouples the
//! Phase 4 success signal from the unrelated 250 s
//! circom-lowering blocker tracked in `circom-lowering-perf.md`
//! (research report §6.5 + §6.6).
//!
//! Tested scenarios (per Reviewer E.2):
//!
//!   (A) **Realistic SHA-like**: 250 distinct heap slots, each
//!       written exactly once and read at least once. Frame size
//!       stays comfortably below the 255-reg cap because the test
//!       reuses dst_regs across LoadHeap reloads (mimicking what
//!       lazy-reload + scratch-reg recycling will do once v1.1
//!       lands). This is the **Phase 4 done gate**.
//!
//!   (B) **Adversarial sequential** is implemented in
//!       `ir-forge/tests/walker_adversarial.rs` because it needs the
//!       Walker to drive frame growth past 255 — that scenario exists
//!       to document the v1.1 escalation path (scratch-reg
//!       recycling), not to gate Phase 4.

use lysis::{bytecode::validate, execute, IrSink, LysisConfig, ProgramBuilder, StubSink};
use memory::{Bn254Fr, FieldElement, FieldFamily};

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

/// Build the realistic SHA-like fixture: 250 distinct slots written
/// once each, then read once each into a recycled scratch reg, then
/// halted. Single-static-store holds (one StoreHeap per slot) and the
/// frame is bounded by the maximum dst_reg used (≤ 200 in this
/// fixture, well below 255).
fn build_sha_like_fixture() -> lysis::Program<Bn254Fr> {
    const N_SLOTS: u16 = 250;
    let mut builder =
        ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256).with_heap_size_hint(N_SLOTS);
    // Pool: 250 distinct field constants.
    for i in 0..N_SLOTS {
        builder.intern_field(fe(u64::from(i)));
    }
    // Phase 1: load each constant into a temporary reg, then spill
    // to its heap slot. We reuse regs in 50-wide chunks so the high
    // water mark on the frame is 50 + a small margin, not 250. This
    // is the "scratch-reg recycling" pattern v1.1 will derive
    // automatically; here we encode it by hand to make the realistic
    // success path explicit.
    for i in 0..N_SLOTS {
        let scratch = (i % 50) as u8;
        builder.load_const(scratch, i);
        builder.store_heap(scratch, i);
    }
    // Phase 2: read each heap slot back into a recycled scratch reg
    // (different chunk to keep the test honest about reg overlap
    // with the writer side).
    for i in 0..N_SLOTS {
        let scratch = 100 + (i % 50) as u8;
        builder.load_heap(scratch, i);
    }
    builder.halt();
    builder.finish()
}

#[test]
fn sha_like_250_slot_program_validates() {
    let program = build_sha_like_fixture();
    validate(&program, &LysisConfig::default()).expect("validate");
    // Header sanity.
    assert_eq!(program.header.version, lysis::VERSION); // 2
    assert_eq!(program.header.heap_size_hint, 250);
}

#[test]
fn sha_like_250_slot_program_executes_without_error() {
    let program = build_sha_like_fixture();
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("execute");
    // Each LoadConst emits one `InstructionKind::Const` to the sink.
    // The fixture has 250 LoadConsts (in Phase 1 above). The
    // StoreHeap / LoadHeap opcodes themselves emit nothing — they
    // only manipulate executor state. The contract under test is:
    // validate + execute return Ok and the executor reads each of
    // the 250 slots without surfacing `LoadFromUnwrittenSlot` /
    // `ValidationFailed`.
    assert_eq!(
        sink.count(),
        250,
        "fixture has 250 LoadConsts; each emits one Const through the sink"
    );
}

#[test]
fn sha_like_250_slot_program_emits_500_heap_ops() {
    // 250 StoreHeap + 250 LoadHeap = 500 heap opcodes total.
    let program = build_sha_like_fixture();
    let stores = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::StoreHeap { .. }))
        .count();
    let loads = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::LoadHeap { .. }))
        .count();
    assert_eq!(stores, 250);
    assert_eq!(loads, 250);
}

#[test]
fn double_store_to_same_slot_is_caught_by_validator() {
    // Manually-crafted programs that violate single-static-store
    // must surface as Rule 13 — defends the contract that Commit 4
    // documented.
    let mut builder = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256).with_heap_size_hint(4);
    builder.intern_field(fe(7));
    builder
        .load_const(0, 0)
        .store_heap(0, 1)
        .store_heap(0, 1) // second store to slot 1 → rule 13
        .halt();
    let program = builder.finish();
    let err = validate(&program, &LysisConfig::default()).unwrap_err();
    assert!(matches!(
        err,
        lysis::LysisError::ValidationFailed { rule: 13, .. }
    ));
}

#[test]
fn slot_beyond_heap_size_hint_is_caught_by_validator() {
    // Rule 12: slot < heap_size_hint. A program that declares
    // hint=4 but stores to slot 99 must be rejected statically.
    let mut builder = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256).with_heap_size_hint(4);
    builder.intern_field(fe(7));
    builder
        .load_const(0, 0)
        .store_heap(0, 99) // slot 99 ≥ 4 → rule 12
        .halt();
    let program = builder.finish();
    let err = validate(&program, &LysisConfig::default()).unwrap_err();
    assert!(matches!(
        err,
        lysis::LysisError::ValidationFailed { rule: 12, .. }
    ));
}

#[test]
fn full_pipeline_round_trips_through_encode_decode() {
    // The 250-slot program survives a bytecode round-trip
    // (encode → decode → validate → execute). This is the smoke
    // that confirms the v2 header byte layout (Commit 2) and the
    // heap opcode encoding (Commit 1) compose correctly under load.
    let program = build_sha_like_fixture();
    let bytes = lysis::encode(&program);
    let redecoded = lysis::decode::<Bn254Fr>(&bytes).expect("decode");
    assert_eq!(redecoded.header.heap_size_hint, 250);
    assert_eq!(redecoded.header.version, lysis::VERSION);
    validate(&redecoded, &LysisConfig::default()).expect("validate post-decode");

    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&redecoded, &[], &LysisConfig::default(), &mut sink).expect("execute post-decode");
}
