use super::*;

// -----------------------------------------------------------------
// compute_frame_size
// -----------------------------------------------------------------

#[test]
fn frame_size_empty_tree_equals_n_params() {
    let t = SymbolicTree::<Bn254Fr>::new();
    let layout = CaptureLayout::default();
    assert_eq!(compute_frame_size(&t, &layout).unwrap(), 0);
}

#[test]
fn frame_size_excludes_slot_and_outer_ref() {
    let mut t = SymbolicTree::<Bn254Fr>::new();
    t.push(SymbolicNode::Const {
        value: fe(0),
        from_slot: Some(SlotId(0)),
    });
    t.push(SymbolicNode::OuterRef(ssa(10)));
    t.push(SymbolicNode::Const {
        value: fe(5),
        from_slot: None,
    }); // literal — counts
    t.n_slots = 1;

    let mut caps = BTreeSet::new();
    caps.insert(SlotId(0));
    let layout = build_capture_layout(&t, &caps);

    // n_params = 1 slot + 1 outer = 2; producing = 1 literal.
    assert_eq!(layout.n_params(), 2);
    assert_eq!(compute_frame_size(&t, &layout).unwrap(), 3);
}

#[test]
fn frame_size_overflow_rejected() {
    let mut t = SymbolicTree::<Bn254Fr>::new();
    for _ in 0..256 {
        t.push(SymbolicNode::Const {
            value: fe(0),
            from_slot: None,
        });
    }
    let layout = CaptureLayout::default();
    assert!(matches!(
        compute_frame_size(&t, &layout),
        Err(ExtractError::FrameOverflow { .. })
    ));
}

#[test]
fn nested_loop_marker_is_not_counted() {
    let mut t = SymbolicTree::<Bn254Fr>::new();
    t.push(SymbolicNode::NestedLoop);
    let layout = CaptureLayout::default();
    assert_eq!(compute_frame_size(&t, &layout).unwrap(), 0);
}
