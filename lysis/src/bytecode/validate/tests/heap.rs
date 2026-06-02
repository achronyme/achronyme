use super::*;

// -----------------------------------------------------------------
// Rule 12 — heap slot < heap_size_hint
// -----------------------------------------------------------------

#[test]
fn rule12_heap_size_zero_rejects_any_heap_op() {
    // No heap declared → any slot is out of bounds.
    let mut builder = b();
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 0) // slot 0 vs cap 0
        .halt();
    let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
}

#[test]
fn rule12_store_oob_rejects() {
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 4) // slot 4 vs cap 4 → out of bounds
        .halt();
    let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
}

#[test]
fn rule12_load_oob_rejects() {
    let mut builder = b().with_heap_size_hint(2);
    builder.load_heap(0, 99).halt();
    let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
}

#[test]
fn rule12_in_bounds_passes() {
    let mut builder = b().with_heap_size_hint(8);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 7) // top-of-range still valid
        .halt();
    check_heap_slot_bounds(&builder.finish()).unwrap();
}

// -----------------------------------------------------------------
// Rule 13 — single-static-store
// -----------------------------------------------------------------

#[test]
fn rule13_load_before_store_rejects() {
    let mut builder = b().with_heap_size_hint(4);
    builder.load_heap(0, 1).halt();
    let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
}

#[test]
fn rule13_double_store_same_slot_rejects() {
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 2)
        .store_heap(0, 2) // second store to slot 2 → reject
        .halt();
    let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
}

#[test]
fn rule13_store_then_load_passes() {
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 2)
        .load_heap(1, 2)
        .halt();
    check_heap_single_static_store(&builder.finish()).unwrap();
}

#[test]
fn rule13_stores_to_different_slots_pass() {
    let mut builder = b().with_heap_size_hint(8);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 1)
        .store_heap(0, 3)
        .store_heap(0, 7)
        .load_heap(1, 1)
        .load_heap(2, 3)
        .load_heap(3, 7)
        .halt();
    check_heap_single_static_store(&builder.finish()).unwrap();
}

#[test]
fn rule13_unwritten_slot_at_end_is_legal() {
    // Slots that end the program in `Unwritten` are legal — the
    // walker may reserve a slot via lookahead and then have the
    // using path pruned. Validator only catches illegal
    // *transitions*.
    let mut builder = b().with_heap_size_hint(8);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 0)
        .load_heap(1, 0)
        .halt(); // slots 1..7 never touched — fine
    check_heap_single_static_store(&builder.finish()).unwrap();
}

#[test]
fn rule13_passes_when_no_heap_declared() {
    // heap_size_hint = 0 → no heap → no rule 13 to check (and the
    // function short-circuits on the cap == 0 fast path).
    let mut builder = b();
    builder.intern_field(one_const());
    builder.load_const(0, 0).halt();
    check_heap_single_static_store(&builder.finish()).unwrap();
}

#[test]
fn full_validate_accepts_well_formed_heap_program() {
    // Smoke that `validate()` itself wires both rules in.
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 1)
        .load_heap(2, 1)
        .halt();
    validate(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn full_validate_rejects_double_store_via_rule_13() {
    let mut builder = b().with_heap_size_hint(4);
    builder.intern_field(one_const());
    builder
        .load_const(0, 0)
        .store_heap(0, 1)
        .store_heap(0, 1)
        .halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
}

// -----------------------------------------------------------------
// Heap-op coverage — rules 12 and 13 cover EmitWitnessCallHeap too.
// -----------------------------------------------------------------

#[test]
fn rule12_witness_call_heap_oob_slot_rejects() {
    let mut builder = b().with_heap_size_hint(4);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![99]) // 99 ≥ 4
        .halt();
    let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
}

#[test]
fn rule12_witness_call_heap_in_bounds_passes() {
    let mut builder = b().with_heap_size_hint(8);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![0, 1, 2, 7])
        .halt();
    check_heap_slot_bounds(&builder.finish()).unwrap();
}

#[test]
fn rule13_witness_call_heap_double_writes_same_slot_rejects() {
    // Two heap-output WitnessCalls writing the same slot must
    // be rejected at the second one (single-static-store).
    let mut builder = b().with_heap_size_hint(4);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![1])
        .emit_witness_call_heap(blob_idx, vec![], vec![1])
        .halt();
    let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
}

#[test]
fn rule13_witness_call_heap_overlap_with_store_heap_rejects() {
    // A StoreHeap to slot 1 followed by a WitnessCallHeap that
    // also writes slot 1 must reject — both consume the same slot.
    let mut builder = b().with_heap_size_hint(4);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder.intern_field(one_const());
    let const_idx_one = builder.intern_artik_bytecode(vec![]); // dummy to not shift
    let _ = const_idx_one;
    builder
        .load_const(0, 0)
        .store_heap(0, 1)
        .emit_witness_call_heap(blob_idx, vec![], vec![1, 2])
        .halt();
    let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
}

#[test]
fn rule13_witness_call_heap_distinct_slots_pass() {
    let mut builder = b().with_heap_size_hint(8);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![0, 1, 2])
        .emit_witness_call_heap(blob_idx, vec![], vec![3, 4, 5])
        .halt();
    check_heap_single_static_store(&builder.finish()).unwrap();
}

#[test]
fn full_validate_accepts_witness_call_heap_program() {
    let mut builder = b().with_heap_size_hint(4);
    let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
    builder
        .emit_witness_call_heap(blob_idx, vec![], vec![0, 1, 2, 3])
        .halt();
    validate(&builder.finish(), &default_config()).unwrap();
}
