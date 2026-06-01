use super::*;

/// Build a body that allocates more than `SPLIT_THRESHOLD` regs in
/// the root frame so the walker is forced to chain a second
/// template. The chain must remain semantically equivalent: every
/// allocated wire is consumed by the final `AssertEq`, so split
/// boundaries that drop a live var would surface as
/// `UndefinedSsaVar`.
#[test]
fn split_fires_on_300_sequential_adds() {
    // x = Input; acc_0 = x; acc_{k+1} = acc_k + x; assert acc_300 == y.
    // 300 Adds → 301 reg allocations in root, comfortably past the
    // 240-reg threshold.
    let mut body = Vec::new();
    body.push(plain(Instruction::Input {
        result: ssa(0),
        name: "y".into(),
        visibility: IrVisibility::Public,
    }));
    body.push(plain(Instruction::Input {
        result: ssa(1),
        name: "x".into(),
        visibility: IrVisibility::Witness,
    }));
    for k in 0..300 {
        body.push(plain(Instruction::Add {
            result: ssa(2 + k),
            lhs: ssa(1 + k),
            rhs: ssa(1),
        }));
    }
    body.push(plain(Instruction::AssertEq {
        result: ssa(0xDEAD),
        lhs: ssa(2 + 299),
        rhs: ssa(0),
        message: None,
    }));

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");
    // ≥ 2 templates means the split fired at least once.
    assert!(
        program.templates.len() >= 2,
        "expected split to chain ≥2 templates, got {}",
        program.templates.len()
    );
    // The split machinery never overflows the frame cap. Pre-emit
    // cost prediction can land a body right at FRAME_CAP.
    for t in &program.templates {
        assert!(
            u32::from(t.frame_size) <= FRAME_CAP,
            "template {} frame_size {} should stay near cap",
            t.id,
            t.frame_size
        );
    }
    // Execute through InterningSink and confirm the materialized
    // stream contains the AssertEq + 300 Adds (post-dedup the Adds
    // collapse to far fewer, but the AssertEq must survive).
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
    let out = sink.materialize();
    let asserts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 1, "AssertEq must survive across the split");
    // The two Inputs (x, y) must also survive — they're side-effects.
    let inputs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
        .count();
    assert_eq!(inputs, 2, "Inputs preserved across split");
}

#[test]
fn split_rejects_template_id_overflow_instead_of_wrapping() {
    let mut walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    walker.templates = (0..=usize::from(u16::MAX))
        .map(|_| TemplateBuf::new(0))
        .collect();
    walker.current = usize::from(u16::MAX);

    let err = walker.perform_split(&[], &[]).unwrap_err();
    assert_eq!(
        err,
        WalkError::OperandOutOfRange {
            kind: "templates",
            limit: u32::from(u16::MAX),
            got: u32::from(u16::MAX) + 1,
        }
    );
}

/// Gap 4: a per-iter unrolled body whose single iteration would
/// itself overflow the frame cap must trigger a mid-iter split. The
/// chain must remain semantically equivalent across iterations:
/// every iteration completes its body, the iter_var literal flows
/// across the split (so SymbolicShift / SymbolicArrayRead still
/// const-fold), and no template ever crosses [`FRAME_CAP`].
#[test]
fn mid_iter_split_handles_wide_per_iter_body() {
    // Per-iter body: SymbolicShift (forces per-iter unroll +
    // exercises the iter_var literal forwarding) + ~250 Adds
    // whose results are not consumed downstream. Each Add still
    // allocates a fresh reg so the alloc tally crosses
    // `FRAME_CAP - FRAME_MARGIN` mid-body, but the SsaVars stay
    // OUT of the live set (no later instruction references them),
    // keeping the capture count well under MAX_CAPTURES.
    const ADD_FAT_LEN: u32 = 250;
    let mut iter_body = Vec::new();
    iter_body.push(ExtendedInstruction::SymbolicShift {
        result_var: ssa(3),
        operand_var: ssa(0),
        shift_var: ssa(2),
        num_bits: 4,
        direction: ShiftDirection::Right,
        span: None,
    });
    for k in 0..ADD_FAT_LEN {
        iter_body.push(plain(Instruction::Add {
            result: ssa(100 + k),
            lhs: ssa(0),
            rhs: ssa(0),
        }));
    }
    // Final SymbolicShift: re-uses iter_var post-split. If the
    // walker_const[iter_var] forwarding is broken, this errors
    // with `SymbolicShiftNotEmittable`.
    iter_body.push(ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(0),
        shift_var: ssa(2),
        num_bits: 4,
        direction: ShiftDirection::Left,
        span: None,
    });
    // Side-effect: AssertEq survives interning across the split.
    iter_body.push(plain(Instruction::AssertEq {
        result: ssa(0xDEAD),
        lhs: ssa(50),
        rhs: ssa(1),
        message: None,
    }));

    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "operand".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "sink".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(2),
            start: 0,
            end: 2,
            body: iter_body,
        },
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");

    assert!(
        program.templates.len() >= 2,
        "expected mid-iter split to chain ≥2 templates, got {}",
        program.templates.len()
    );

    for t in &program.templates {
        assert!(
            u32::from(t.frame_size) <= FRAME_CAP,
            "template {} frame_size {} should stay within cap",
            t.id,
            t.frame_size
        );
    }

    // Both iterations must complete — at least one AssertEq per
    // iteration survives interning. The exact count after dedup is
    // ≥ 1; we assert ≥ 1 so the test is robust to interner tuning
    // but still proves the mid-split body executes through.
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
    let out = sink.materialize();
    let asserts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
        .count();
    assert!(
        asserts >= 1,
        "AssertEq must survive mid-iter splits, got {}",
        asserts
    );
    // Both Inputs survive (side-effects).
    let inputs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
        .count();
    assert_eq!(inputs, 2, "Inputs preserved across mid-iter split");
    // Decomposes survive — one per iteration of the rolled loop,
    // each in a different post-split frame for iters that crossed
    // a boundary. Lower bound: 1 (post-interning the structurally
    // identical decomposes may collapse).
    let decomps = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
        .count();
    assert!(
        decomps >= 1,
        "Decompose from SymbolicShift must survive mid-iter split, got {}",
        decomps
    );
}
