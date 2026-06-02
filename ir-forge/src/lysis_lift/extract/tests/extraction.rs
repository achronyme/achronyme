use super::*;

// -----------------------------------------------------------------
// extract_template — end-to-end from BTA output
// -----------------------------------------------------------------

#[test]
fn extract_produces_spec_matching_layout() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 5, fe);
    let (skeleton, captures) = match c.binding_time {
        BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
        BindingTime::DataDependent => panic!("expected Uniform"),
    };
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let spec = extract_template(&skeleton, &captures, &mut reg).unwrap();

    assert_eq!(spec.n_params(), 1);
    assert_eq!(spec.layout.entries[0], CaptureKind::Slot(SlotId(0)));
    // Body tree: slot Const + Op(Mul). frame_size = 1 (n_params) + 1 (Op producing) = 2.
    assert_eq!(spec.frame_size, 2);
    assert_eq!(reg.len(), 1);
}

#[test]
fn extract_preserves_skeleton() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(99), // outer ref
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 3, fe);
    let (skeleton, captures) = match c.binding_time {
        BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
        _ => panic!(),
    };
    let orig_len = skeleton.nodes.len();
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let spec = extract_template(&skeleton, &captures, &mut reg).unwrap();
    assert_eq!(spec.skeleton.nodes.len(), orig_len);

    // Layout: slot 0 first, then outer ref ssa(99).
    assert_eq!(spec.n_params(), 2);
    assert!(matches!(
        spec.layout.entries[0],
        CaptureKind::Slot(SlotId(0))
    ));
    assert!(matches!(spec.layout.entries[1], CaptureKind::OuterRef(v) if v == ssa(99)));
}

#[test]
fn two_independent_extractions_get_different_ids() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c1 = classify(ssa(0), &body, 0, 5, fe);
    let c2 = classify(ssa(0), &body, 0, 5, fe);
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let (s1, k1) = match c1.binding_time {
        BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
        _ => panic!(),
    };
    let (s2, k2) = match c2.binding_time {
        BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
        _ => panic!(),
    };
    let a = extract_template(&s1, &k1, &mut reg).unwrap();
    let b = extract_template(&s2, &k2, &mut reg).unwrap();
    // No structural dedup — even identical bodies get distinct ids.
    assert_ne!(a.id, b.id);
    assert_eq!(reg.len(), 2);
}
