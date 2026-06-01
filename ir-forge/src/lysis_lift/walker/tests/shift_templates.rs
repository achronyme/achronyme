use super::*;

#[test]
fn synthesises_witness_when_symbolic_array_read_slot_unbound() {
    // array_slots contains an SsaVar that was never pre-emitted —
    // the read-side now mirrors `emit_symbolic_indexed_effect` and
    // synthesises a witness `LoadInput` on demand. The output
    // stream materialises one Input for the slot and the read
    // result aliases it.
    let body = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 1,
        body: vec![ExtendedInstruction::SymbolicArrayRead {
            result_var: ssa(1),
            // ssa(99) is never bound by any earlier instruction;
            // the read-side now synthesises it as a witness wire.
            array_slots: vec![ssa(99)],
            index_var: ssa(0),
            span: None,
        }],
    }];
    let out = run(&body);

    // One synthesised Input (`__lysis_sym_slot_99`).
    let inputs: Vec<&str> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::Input { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(inputs.len(), 1, "one synthesised slot input");
    assert!(
        inputs[0].starts_with("__lysis_sym_slot_"),
        "synth name prefix: got {:?}",
        inputs[0]
    );
}

#[test]
fn unfolds_symbolic_shift_per_iteration() {
    // Body: for i in 0..3 { sink := operand >> i }. Per-iteration
    // the walker resolves shift_var=i to a literal, decomposes
    // operand to 4 bits, and recomposes the kept high bits. We
    // count Decompose ops (one per iter, no dedup at executor
    // level since each iter's emission is structurally unique
    // until BTA Stage 4 lifts it) and AssertEqs (one per iter).
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
            end: 3,
            body: vec![
                ExtendedInstruction::SymbolicShift {
                    result_var: ssa(3),
                    operand_var: ssa(0),
                    shift_var: ssa(2),
                    num_bits: 4,
                    direction: ShiftDirection::Right,
                    span: None,
                },
                plain(Instruction::AssertEq {
                    result: ssa(4),
                    lhs: ssa(1),
                    rhs: ssa(3),
                    message: None,
                }),
            ],
        },
    ];
    let out = run(&body);

    // 3 Decomposes (one per iteration of the rolled loop).
    let decomps = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
        .count();
    assert_eq!(decomps, 3, "3 Decomposes, one per iteration");

    // 3 AssertEqs (one per iter). Each rhs picks up a different
    // recomposed wire because the kept-bit set + powers vary.
    let asserts: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(asserts.len(), 3, "3 AssertEqs");
    let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
    assert_eq!(lhs_set.len(), 1, "all 3 lhs share the sink reg");
}

#[test]
fn unfolds_symbolic_shift_left_with_affine_amount() {
    // Body: for i in 0..3 { sink := operand << (i + 1) }. Index is
    // computed inside the body via Const(1) + Add; walker_const
    // tracks the fold and the shift resolves to 1, 2, 3.
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
            end: 3,
            body: vec![
                plain(Instruction::Const {
                    result: ssa(3),
                    value: fe(1),
                }),
                plain(Instruction::Add {
                    result: ssa(4),
                    lhs: ssa(2),
                    rhs: ssa(3),
                }),
                ExtendedInstruction::SymbolicShift {
                    result_var: ssa(5),
                    operand_var: ssa(0),
                    shift_var: ssa(4),
                    num_bits: 4,
                    direction: ShiftDirection::Left,
                    span: None,
                },
                plain(Instruction::AssertEq {
                    result: ssa(6),
                    lhs: ssa(1),
                    rhs: ssa(5),
                    message: None,
                }),
            ],
        },
    ];
    let out = run(&body);

    // Each iteration runs a Decompose. 3 iterations → 3 Decomposes.
    let decomps = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
        .count();
    assert_eq!(decomps, 3, "3 Decomposes, one per iteration");

    let asserts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 3, "3 AssertEqs");
}

#[test]
fn rejects_symbolic_shift_when_amount_not_const_foldable() {
    // shift_var depends on a runtime Input (not a loop-iter const)
    // — walker can't resolve. Expect the dedicated error.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "operand".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "runtime_shift".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(2),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicShift {
                result_var: ssa(3),
                operand_var: ssa(0),
                shift_var: ssa(1),
                num_bits: 4,
                direction: ShiftDirection::Right,
                span: None,
            }],
        },
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body.clone()).expect_err("should refuse");
    assert!(
        matches!(err, WalkError::SymbolicShiftNotEmittable),
        "got {err:?}"
    );
}

#[test]
fn symbolic_shift_full_drop_yields_zero_const() {
    // shift = num_bits → result is the constant zero. The walker
    // emits one LoadConst(0) per iteration and no Decompose.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "operand".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(8),
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(2),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicShift {
                result_var: ssa(3),
                operand_var: ssa(0),
                // shift_var bound to the source-level Const(8) so
                // walker_const resolves to 8 — equals num_bits.
                shift_var: ssa(1),
                num_bits: 8,
                direction: ShiftDirection::Right,
                span: None,
            }],
        },
    ];
    let out = run(&body);

    let decomps = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
        .count();
    assert_eq!(decomps, 0, "no Decompose when shift drops everything");
}

#[test]
fn refuses_template_call_with_outputs() {
    // The Option B lift uses side-effects only — non-empty
    // outputs would require `Opcode::TemplateOutput` wiring,
    // which is not implemented. Verify the walker rejects them
    // rather than silently miscompiling.
    let body = vec![ExtendedInstruction::TemplateCall {
        template_id: crate::TemplateId(0),
        captures: vec![],
        outputs: vec![ssa(0)],
    }];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker
        .lower(body.clone())
        .expect_err("should refuse outputs");
    assert_eq!(err, WalkError::TemplateOutputsNotSupported);
}

#[test]
fn rejects_template_body_captures_mismatch() {
    // n_params declares 2 but captures has 1 → pipeline corruption.
    let body = vec![ExtendedInstruction::TemplateBody {
        id: crate::TemplateId(1),
        frame_size: 4,
        n_params: 2,
        captures: vec![ssa(0)],
        body: vec![],
    }];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker
        .lower(body.clone())
        .expect_err("should refuse mismatch");
    assert!(matches!(
        err,
        WalkError::TemplateCapturesMismatch {
            n_params: 2,
            captures_len: 1
        }
    ));
}

#[test]
fn walker_lower_lifts_uniform_loops_internally() {
    // Stage 4 wiring: Walker::lower runs lift_uniform_loops as
    // its first step. A bare Uniform LoopUnroll handed to the
    // walker should land as a 2-template program (Template 0
    // root wrapper + Template 1 lifted body), even though the
    // caller never built the lift output explicitly.
    let outer_input = ssa(0);
    let iter_var = ssa(1);
    let body = vec![
        plain(Instruction::Input {
            result: outer_input,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start: 0,
            end: 3,
            body: vec![plain(Instruction::Mul {
                result: ssa(2),
                lhs: outer_input,
                rhs: outer_input,
            })],
        },
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower OK");
    // Lift produced a template; walker has root + lifted = 2.
    assert_eq!(program.templates.len(), 2);
    assert_eq!(program.templates[1].n_params, 1, "outer_input captured");
}

#[test]
fn lowers_template_body_plus_call_pair() {
    // Lift-shaped fixture: an outer Plain(Input) becomes an
    // OuterRef capture; a TemplateBody wraps a tiny LoopUnroll
    // that uses the captured input; a TemplateCall instantiates
    // it. The walker should emit one root template (Template 0,
    // the wrapper) plus the lifted template body. The execution
    // dispatch is exercised by lysis e2e tests; here we just
    // verify the walker doesn't error and produces a non-empty
    // program with the expected number of templates.
    let outer_input = ssa(0);
    let iter_var = ssa(1);
    let lifted = ExtendedInstruction::TemplateBody {
        id: crate::TemplateId(1),
        frame_size: 4,
        n_params: 1,
        captures: vec![outer_input],
        body: vec![ExtendedInstruction::LoopUnroll {
            iter_var,
            start: 0,
            end: 2,
            body: vec![plain(Instruction::Mul {
                result: ssa(2),
                lhs: outer_input,
                rhs: outer_input,
            })],
        }],
    };
    let body = vec![
        plain(Instruction::Input {
            result: outer_input,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        lifted,
        ExtendedInstruction::TemplateCall {
            template_id: crate::TemplateId(1),
            captures: vec![outer_input],
            outputs: vec![],
        },
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower OK");
    // Templates: 0 (root wrapper) + 1 (lifted) = 2.
    assert_eq!(program.templates.len(), 2);
    // Template 1 carries n_params=1 (the captured outer input).
    assert_eq!(program.templates[1].n_params, 1);
    assert!(program.templates[1].frame_size >= 1);
}
