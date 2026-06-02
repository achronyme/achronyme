use super::*;

// -----------------------------------------------------------------
// lift_uniform_loops
// -----------------------------------------------------------------

#[test]
fn lift_pass_through_for_non_loop_instructions() {
    // Plain instructions stay unchanged; no template allocated.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Const {
            result: ssa(0),
            value: fe(7),
        }
        .into(),
        Instruction::Add {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into(),
    ];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body.clone(), &mut reg, &FixedBitSet::new()).unwrap();
    assert_eq!(lifted.len(), 2);
    assert!(matches!(lifted[0], ExtendedInstruction::Plain(_)));
    assert!(matches!(lifted[1], ExtendedInstruction::Plain(_)));
    assert!(reg.is_empty());
}

#[test]
fn lift_simple_uniform_loop_produces_template_pair() {
    // for i in 0..3 { v = i * outer_ref }. Body uses iter_var
    // (slot capture) + outer_ref (OuterRef capture). Lift should
    // produce ONE TemplateBody (containing the LoopUnroll) and
    // ONE TemplateCall whose captures = [outer_ref].
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 3,
        body: vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),  // iter_var
            rhs: ssa(99), // outer ref
        }
        .into()],
    }];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();

    assert_eq!(lifted.len(), 2, "expected TemplateBody + TemplateCall");
    let (id_in_body, body_inner) = match &lifted[0] {
        ExtendedInstruction::TemplateBody {
            id,
            n_params,
            captures,
            body,
            ..
        } => {
            assert_eq!(*n_params, 1, "one OuterRef capture");
            assert_eq!(captures, &vec![ssa(99)]);
            assert_eq!(body.len(), 1, "body wraps the original LoopUnroll");
            assert!(matches!(body[0], ExtendedInstruction::LoopUnroll { .. }));
            (*id, body)
        }
        other => panic!("expected TemplateBody, got {other:?}"),
    };
    match &lifted[1] {
        ExtendedInstruction::TemplateCall {
            template_id,
            captures,
            outputs,
        } => {
            assert_eq!(*template_id, id_in_body);
            assert_eq!(captures, &vec![ssa(99)]);
            assert!(outputs.is_empty());
        }
        other => panic!("expected TemplateCall, got {other:?}"),
    }

    assert_eq!(reg.len(), 1);
    let spec = reg.get(id_in_body).expect("spec stored");
    assert_eq!(spec.n_params(), 1);
    // Don't tighten frame_size assertion — the budget depends on
    // skeleton's producing-node count + iter_var slot, which is a
    // conservative over-approximation by design.
    assert!(spec.frame_size >= 1);

    // Sanity: the template body's wrapped LoopUnroll preserved
    // its iter_var and bounds.
    match &body_inner[0] {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            ..
        } => {
            assert_eq!(*iter_var, ssa(0));
            assert_eq!(*start, 0);
            assert_eq!(*end, 3);
        }
        _ => unreachable!(),
    }
}

#[test]
fn lift_single_iteration_loop_stays_as_unroll() {
    // BTA short-circuits `iterations < 2` to `DataDependent`.
    // A `0..1` loop therefore never gets a template; it stays
    // inline as a LoopUnroll. Verifies the DataDependent branch
    // of the lift dispatch.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 1,
        body: vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(99),
        }
        .into()],
    }];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();

    assert!(reg.is_empty(), "no template allocated for DataDependent");
    assert_eq!(lifted.len(), 1);
    assert!(matches!(lifted[0], ExtendedInstruction::LoopUnroll { .. }));
}

#[test]
fn lift_falls_back_to_inline_when_body_exceeds_frame_cap() {
    // Construct a Uniform loop whose body's symbolic skeleton
    // would need more than `MAX_FRAME_SIZE = 255` producing
    // slots — `lift_uniform_to_template` returns `FrameOverflow`,
    // and `lift_one` must catch it and keep the loop inline as
    // if it had classified `DataDependent`. Other lift errors
    // still propagate.
    //
    // 260 sequential Add instructions all producing fresh SSA
    // vars from the iter_var give a skeleton with 260 producing
    // Add nodes, comfortably over the cap.
    const N_ADDS: u32 = 260;
    let mut inner_body: Vec<ExtendedInstruction<Bn254Fr>> = Vec::with_capacity(N_ADDS as usize);
    for k in 0..N_ADDS {
        inner_body.push(
            Instruction::Add {
                result: ssa(100 + k),
                lhs: ssa(0),  // iter_var (slot capture)
                rhs: ssa(99), // outer ref capture
            }
            .into(),
        );
    }
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 3,
        body: inner_body,
    }];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();

    assert!(reg.is_empty(), "no template allocated when lift overflows");
    assert_eq!(lifted.len(), 1, "single inline LoopUnroll fallback");
    match &lifted[0] {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        } => {
            assert_eq!(*iter_var, ssa(0));
            assert_eq!(*start, 0);
            assert_eq!(*end, 3);
            assert_eq!(body.len(), N_ADDS as usize);
        }
        other => panic!("expected fallback LoopUnroll, got {other:?}"),
    }
}

#[test]
fn lift_recurses_into_nested_loops_bottom_up() {
    // Outer loop wraps an inner loop whose body references its
    // own iter_var. After lift, the inner becomes a template,
    // and the outer sees a TemplateCall in its body — outer's
    // classification then runs against that.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 4,
        body: vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(1),
            start: 0,
            end: 3,
            body: vec![Instruction::Mul {
                result: ssa(2),
                lhs: ssa(1), // inner iter_var
                rhs: ssa(1), // inner iter_var
            }
            .into()],
        }],
    }];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();

    // Inner produced one template; outer may have produced
    // another depending on how its inner lifts.
    assert!(!reg.is_empty(), "at least the inner uniform lifted");
    assert!(!lifted.is_empty());
}

#[test]
fn lift_independent_loops_get_distinct_template_ids() {
    // Two sibling Uniform loops should produce two TemplateBodies
    // with different ids. (No structural dedup yet; a future pass
    // will hash skeletons and merge structurally identical ones.)
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 3,
            body: vec![Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(99),
            }
            .into()],
        },
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(2),
            start: 0,
            end: 3,
            body: vec![Instruction::Mul {
                result: ssa(3),
                lhs: ssa(2),
                rhs: ssa(99),
            }
            .into()],
        },
    ];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();
    assert_eq!(lifted.len(), 4, "two TemplateBody + two TemplateCall pairs");
    assert_eq!(reg.len(), 2, "two distinct template ids");
    let ids: Vec<TemplateId> = lifted
        .iter()
        .filter_map(|inst| match inst {
            ExtendedInstruction::TemplateBody { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn lift_keeps_loop_inline_when_body_var_escapes_to_sibling() {
    // Loop body defines ssa(10); a sibling instruction *after* the
    // loop consumes ssa(10). Lifting would seal ssa(10) inside the
    // template frame and fault the downstream consumer. The walker
    // must recognise the escape and keep the LoopUnroll verbatim.
    //
    // Walking in reverse: the consumer's reference to ssa(10) lands
    // in `acc` first; when the LoopUnroll is reached, the escape
    // check finds `body_defined ∩ acc` non-empty and falls back.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 3,
            body: vec![Instruction::Mul {
                result: ssa(10), // defined inside, consumed below
                lhs: ssa(0),
                rhs: ssa(99),
            }
            .into()],
        },
        Instruction::Add {
            result: ssa(11),
            lhs: ssa(10),
            rhs: ssa(99),
        }
        .into(),
    ];
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let lifted = lift_uniform_loops(body, &mut reg, &FixedBitSet::new()).unwrap();
    assert_eq!(lifted.len(), 2, "loop kept verbatim, sibling preserved");
    assert!(
        matches!(lifted[0], ExtendedInstruction::LoopUnroll { .. }),
        "first instruction must remain a LoopUnroll, not a TemplateCall",
    );
    assert!(reg.is_empty(), "no template should be allocated");
}
