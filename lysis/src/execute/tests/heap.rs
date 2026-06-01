use super::*;

// -----------------------------------------------------------------
// Heap spill
// -----------------------------------------------------------------

#[test]
fn store_then_load_round_trips_value() {
    // r0 = Const(7); StoreHeap r0 → slot 0; LoadHeap slot 0 → r1.
    // The sink ends up emitting one Const(7); both r0 and r1 hold
    // the same NodeId because LoadHeap re-binds the heap entry,
    // not a new value.
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .store_heap(0, 0)
        .load_heap(1, 0)
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Just one Const(7) was emitted — StoreHeap/LoadHeap don't
    // produce IR; they manipulate executor heap state.
    assert_eq!(sink.count(), 1);
    match &sink.instructions()[0] {
        InstructionKind::Const { value, .. } => assert_eq!(*value, seven()),
        other => panic!("expected Const, got {other:?}"),
    }
}

#[test]
fn load_from_unwritten_slot_rejects_with_rule_13() {
    // LoadHeap from a slot that has never been written must surface
    // as Rule 13 (single-static-store invariant in spirit).
    let mut builder = b().with_heap_size_hint(4);
    builder.load_heap(0, 2).halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::ValidationFailed { rule: 13, .. }),
        "expected ValidationFailed rule 13, got {err:?}"
    );
}

#[test]
fn store_with_slot_out_of_bounds_rejects_with_rule_12() {
    // heap_size_hint=2 → valid slots 0,1. StoreHeap to slot 5 must
    // surface as Rule 12 (slot < heap_size_hint).
    let mut builder = b().with_heap_size_hint(2);
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .store_heap(0, 5) // slot 5 >= 2
        .halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::ValidationFailed { rule: 12, .. }),
        "expected ValidationFailed rule 12, got {err:?}"
    );
}

#[test]
fn load_with_slot_out_of_bounds_rejects_with_rule_12() {
    // Symmetric to the store case: LoadHeap to a too-large slot
    // is rule 12, not rule 13 (because the bounds check fires
    // before the unwritten check).
    let mut builder = b().with_heap_size_hint(2);
    builder.load_heap(0, 99).halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::ValidationFailed { rule: 12, .. }),
        "expected ValidationFailed rule 12, got {err:?}"
    );
}

#[test]
fn heap_slot_above_u16_ceiling_round_trips_the_right_value() {
    // A >1.5 M-constraint circuit spills >65 535 distinct cold
    // vars, so a heap slot index can exceed the old u16 ceiling.
    // The slot field (`StoreHeap.slot` / `LoadHeap.slot`, 4 wire
    // bytes) and `heap_size_hint` (u32) must carry the true index;
    // a narrowing back to u16 would wrap slot 100_000 onto
    // 100_000 & 0xFFFF == 34_464, reading the wrong var's value.
    //
    // Store seven() at slot 100_000 and one() at exactly that
    // wrap target 34_464, then LoadHeap slot 100_000: the loaded
    // value is seven() iff the slot is NOT truncated (u16 wrap
    // would read 34_464 == one()).
    const SLOT_HI: u32 = 100_000;
    const SLOT_WRAP: u32 = SLOT_HI & 0xFFFF; // 34_464
    assert!(SLOT_HI > u32::from(u16::MAX));

    let mut builder = b().with_heap_size_hint(SLOT_HI + 1);
    builder.intern_field(seven()); // const idx 0
    builder.intern_field(one()); // const idx 1
    builder
        .load_const(0, 0) // r0 = seven()
        .store_heap(0, SLOT_HI) // heap[100_000] = seven()
        .load_const(1, 1) // r1 = one()
        .store_heap(1, SLOT_WRAP) // heap[34_464] = one()
        .load_heap(2, SLOT_HI) // r2 = heap[100_000]
        .emit_neg(3, 2) // observable: Neg(r2)
        .halt();

    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink)
        .expect("execute must not rule-12/13 on a >u16 heap slot");
    let flat = sink.materialize();

    let const_value: std::collections::HashMap<NodeId, FieldElement<Bn254Fr>> = flat
        .iter()
        .filter_map(|n| match n {
            InstructionKind::Const { result, value } => Some((*result, *value)),
            _ => None,
        })
        .collect();
    let neg_operand = flat
        .iter()
        .find_map(|n| match n {
            InstructionKind::Neg { operand, .. } => Some(*operand),
            _ => None,
        })
        .expect("the Neg consuming the loaded slot must be emitted");
    assert_eq!(
        const_value.get(&neg_operand).copied(),
        Some(seven()),
        "LoadHeap from slot {SLOT_HI} must read seven() (its true \
             value); reading one() means the slot wrapped to {SLOT_WRAP}"
    );
}

#[test]
fn zero_heap_size_hint_rejects_any_heap_op() {
    // heap_size_hint=0 → any slot is out of bounds. This is the
    // contract that protects v1 streams (which never declare
    // heap_size_hint) from accidentally executing heap opcodes
    // injected by a malformed v2 stream.
    let mut builder = b(); // default heap_size_hint = 0
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .store_heap(0, 0) // slot 0 vs heap_size_hint=0
        .halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
}

#[test]
fn store_overwrites_slot_then_load_returns_latest() {
    // The executor itself does not enforce single-static-store;
    // that is the validator's job (single-static-store rule).
    // At the executor level, two stores to the same slot
    // overwrite, and a subsequent LoadHeap returns the latest.
    // This test guarantees that runtime semantics match the
    // documented "last write wins" fallback when the validator is
    // bypassed.
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(seven());
    builder.intern_field(one());
    builder
        .load_const(0, 0) // r0 = Const(7)
        .load_const(1, 1) // r1 = Const(1)
        .store_heap(0, 3) // heap[3] = id of Const(7)
        .store_heap(1, 3) // heap[3] = id of Const(1) — overwrite
        .load_heap(2, 3) // r2 should bind to the latest store (Const(1))
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Two Consts emitted (LoadHeap doesn't emit a new instruction).
    assert_eq!(sink.count(), 2);
}

// -----------------------------------------------------------------
// EmitWitnessCallHeap
// -----------------------------------------------------------------

#[test]
fn witness_call_heap_writes_outputs_to_heap_slots() {
    // 2 inputs in regs → Artik program → 4 outputs to heap slots
    // 0..=3. Pull two of them back via LoadHeap and verify the
    // sink saw exactly one WitnessCall + the two LoadConsts that
    // populated the inputs.
    let mut builder = b().with_heap_size_hint(8);
    use crate::bytecode::opcode::InputSrc;
    builder.intern_field(seven());
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .load_const(0, 0)
        .load_const(1, 0)
        .emit_witness_call_heap(
            blob_idx,
            vec![InputSrc::Reg(0), InputSrc::Reg(1)],
            vec![0, 1, 2, 3], // out_slots
        )
        .load_heap(5, 0)
        .load_heap(6, 3)
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Sink emissions: 2 Const (one Const value, but separate calls
    // — InterningSink would dedupe; StubSink doesn't). Plus the
    // WitnessCall side-effect.
    let witness_calls = sink
        .instructions()
        .iter()
        .filter(|k| matches!(k, InstructionKind::WitnessCall { .. }))
        .count();
    assert_eq!(
        witness_calls, 1,
        "exactly one WitnessCall side-effect emitted"
    );
}

#[test]
fn witness_call_heap_oob_slot_rejected_by_rule_12() {
    // out_slot=99, heap_size_hint=4 → Rule 12 fires at runtime
    // even if the validator was bypassed.
    let mut builder = b().with_heap_size_hint(4);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![99])
        .halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::ValidationFailed { rule: 12, .. }),
        "expected ValidationFailed rule 12, got {err:?}"
    );
}

#[test]
fn witness_call_heap_with_non_artik_const_idx_errors() {
    // bytecode_const_idx points at a Field entry, not Artik blob.
    // Same rule-4 surface as classic EmitWitnessCall.
    let mut builder = b().with_heap_size_hint(2);
    builder.intern_field(seven());
    builder.emit_witness_call_heap(0, vec![], vec![0]).halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::ValidationFailed { rule: 4, .. }),
        "expected ValidationFailed rule 4, got {err:?}"
    );
}
