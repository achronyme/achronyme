use super::*;

// -----------------------------------------------------------------
// CaptureLayout
// -----------------------------------------------------------------

#[test]
fn capture_layout_empty_when_tree_empty() {
    let t = SymbolicTree::<Bn254Fr>::new();
    let captures = BTreeSet::new();
    let layout = build_capture_layout(&t, &captures);
    assert!(layout.is_empty());
    assert_eq!(layout.n_params(), 0);
}

#[test]
fn capture_layout_orders_slots_then_outer_refs() {
    // Skeleton with mixed slot consts + outer refs.
    let mut t = SymbolicTree::<Bn254Fr>::new();
    t.push(SymbolicNode::Const {
        value: fe(0),
        from_slot: Some(SlotId(0)),
    });
    t.push(SymbolicNode::OuterRef(ssa(50)));
    t.push(SymbolicNode::OuterRef(ssa(40)));
    t.push(SymbolicNode::OuterRef(ssa(50))); // dup
    t.n_slots = 1;

    let mut caps = BTreeSet::new();
    caps.insert(SlotId(0));

    let layout = build_capture_layout(&t, &caps);
    assert_eq!(layout.entries.len(), 3);
    assert!(matches!(layout.entries[0], CaptureKind::Slot(SlotId(0))));
    assert!(matches!(layout.entries[1], CaptureKind::OuterRef(v) if v == ssa(50)));
    assert!(matches!(layout.entries[2], CaptureKind::OuterRef(v) if v == ssa(40)));
}

#[test]
fn capture_layout_is_deterministic() {
    let mut t = SymbolicTree::<Bn254Fr>::new();
    t.push(SymbolicNode::OuterRef(ssa(99)));
    t.push(SymbolicNode::OuterRef(ssa(88)));

    let caps = BTreeSet::new();
    let l1 = build_capture_layout(&t, &caps);
    let l2 = build_capture_layout(&t, &caps);
    assert_eq!(l1.entries.len(), l2.entries.len());
    for (a, b) in l1.entries.iter().zip(l2.entries.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn slot_index_and_outer_ref_index_lookups() {
    let mut t = SymbolicTree::<Bn254Fr>::new();
    t.push(SymbolicNode::Const {
        value: fe(0),
        from_slot: Some(SlotId(2)),
    });
    t.push(SymbolicNode::OuterRef(ssa(7)));
    t.n_slots = 1;
    let mut caps = BTreeSet::new();
    caps.insert(SlotId(2));

    let layout = build_capture_layout(&t, &caps);
    assert_eq!(layout.slot_index(SlotId(2)), Some(0));
    assert_eq!(layout.slot_index(SlotId(99)), None);
    assert_eq!(layout.outer_ref_index(ssa(7)), Some(1));
    assert_eq!(layout.outer_ref_index(ssa(99)), None);
}
