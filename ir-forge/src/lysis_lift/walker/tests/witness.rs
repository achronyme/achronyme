use super::*;

#[test]
fn lowers_witness_call_with_blob_and_multiple_outputs() {
    // Blob content is not validated at this layer — the walker just
    // interns the bytes and lets the executor decode.
    let blob = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![ssa(1), ssa(2), ssa(3)],
            inputs: vec![ssa(0)],
            program_bytes: blob,
        }))),
    ];
    // `run` goes through a full execute via InterningSink. WitnessCall
    // is a side-effect that produces OPAQUE output slots — the
    // InterningSink does NOT dedupe it. We expect one WitnessCall in
    // the materialized output with 3 output slots.
    let out = run(&body);
    let calls: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::WitnessCall(call) => Some(call.outputs.len()),
            _ => None,
        })
        .collect();
    assert_eq!(calls, vec![3]);
}

#[test]
fn lowers_div_to_emit_div() {
    // Field `Div` lowers to `Opcode::EmitDiv`, which the executor
    // materialises as `Instruction::Div` for the sink; the R1CS
    // backend then lowers that via `divide_lcs` (witness-side
    // inverse hint + `rhs * inv = 1` constraint).
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "a".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Div {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    let divs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Div { .. }))
        .count();
    assert_eq!(divs, 1, "Div survives the walker");
}

#[test]
fn lowers_int_div_and_int_mod() {
    // SHA-256 emits IntDiv/IntMod, so the bytecode carries
    // EmitIntDiv / EmitIntMod opcodes. Verify the materialized
    // stream contains both.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "a".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::IntDiv {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            max_bits: 8,
        }),
        plain(Instruction::IntMod {
            result: ssa(3),
            lhs: ssa(0),
            rhs: ssa(1),
            max_bits: 8,
        }),
    ];
    let out = run(&body);
    let divs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IntDiv { .. }))
        .count();
    let mods = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IntMod { .. }))
        .count();
    assert_eq!(divs, 1, "IntDiv survives the walker");
    assert_eq!(mods, 1, "IntMod survives the walker");
}

#[test]
fn refuses_int_div_max_bits_overflow() {
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "a".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::IntDiv {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            max_bits: 300,
        }),
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body).expect_err("max_bits > u8 should refuse");
    assert!(matches!(
        err,
        WalkError::OperandOutOfRange {
            kind: "IntDiv.max_bits",
            ..
        }
    ));
}

#[test]
fn refuses_range_check_bits_overflow() {
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::RangeCheck {
            result: ssa(1),
            operand: ssa(0),
            bits: 300,
        }),
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body.clone()).expect_err("should refuse");
    assert_eq!(
        err,
        WalkError::OperandOutOfRange {
            kind: "RangeCheck.bits",
            limit: 255,
            got: 300,
        }
    );
}

#[test]
fn lowers_witness_call_empty_inputs() {
    // Zero inputs, single output.
    let body = vec![plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![ssa(0)],
        inputs: vec![],
        program_bytes: vec![0xFF],
    })))];
    let out = run(&body);
    let call_count = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::WitnessCall(_)))
        .count();
    assert_eq!(call_count, 1);
}

#[test]
fn witness_call_under_threshold_emits_classic_variant() {
    // 200 outputs is exactly at the threshold; classic path
    // because `outputs.len() > MAX_WITNESS_OUTPUTS_INLINE` is
    // false when outputs.len() == 200.
    let outputs: Vec<SsaVar> = (0..200u32).map(ssa).collect();
    let body = vec![plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs,
        inputs: vec![],
        program_bytes: vec![0xFF],
    })))];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");

    let classic_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCall { .. }))
        .count();
    let heap_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCallHeap { .. }))
        .count();
    assert_eq!(classic_count, 1);
    assert_eq!(heap_count, 0);
    assert_eq!(
        program.header.heap_size_hint, 0,
        "classic variant should not allocate heap slots"
    );
}

#[test]
fn witness_call_over_threshold_emits_heap_variant() {
    // 256 outputs (canonical SHA-256 case): walker must switch
    // to the heap-output variant because classic would need 256
    // fresh regs and overflow `FRAME_CAP = 255`.
    let outputs: Vec<SsaVar> = (0..256u32).map(ssa).collect();
    let body = vec![plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs,
        inputs: vec![],
        program_bytes: vec![0xFF],
    })))];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");

    let classic_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCall { .. }))
        .count();
    let heap_calls: Vec<&lysis::Opcode> = program
        .body
        .iter()
        .map(|i| &i.opcode)
        .filter(|op| matches!(op, lysis::Opcode::EmitWitnessCallHeap { .. }))
        .collect();
    assert_eq!(classic_count, 0);
    assert_eq!(heap_calls.len(), 1);
    if let lysis::Opcode::EmitWitnessCallHeap { out_slots, .. } = heap_calls[0] {
        assert_eq!(
            out_slots.len(),
            256,
            "256 outputs land in 256 distinct slots"
        );
    }
    assert_eq!(
        program.header.heap_size_hint, 256,
        "heap_size_hint reflects allocated slots"
    );
}

#[test]
fn witness_call_routes_to_heap_when_cold_inputs_would_overflow_classic() {
    // Regression: a wide-output `WitnessCall` whose `outputs.len()`
    // alone would fit the post-split frame, but whose *cold
    // inputs* (spilled to the heap by the split that the call's
    // own reg cost triggered, then faulted back in via `LoadHeap`
    // on the classic path) push `outputs + cold_inputs` over
    // `FRAME_CAP`. The emit-arm guard must account for the
    // classic path's cold-input reg cost — not just `outputs` —
    // and route to the always-fitting heap path.
    //
    // 60 producers (all live, all consumed only as the call's
    // inputs) → the call's `cost = 200` trips the pre-emit split;
    // `do_split` keeps the first MAX_CAPTURES_HOT (48) hot and
    // spills the remaining 12 to the heap. On the post-split
    // frame `next_slot = 48`, so `48 + 200 + margin < FRAME_CAP`
    // (the outputs-only guard stays false) — but the classic path
    // would then `resolve()` the 12 cold inputs (+12 regs) and
    // allocate 200 outputs, overflowing 255. Pre-fix this panics
    // in `lower()`; the guard must instead pick the heap variant.
    let n_inputs = 60u32;
    let mut body: Vec<ExtendedInstruction<Bn254Fr>> = (0..n_inputs)
        .map(|i| {
            plain(Instruction::Const {
                result: ssa(i),
                value: fe(u64::from(i) + 1),
            })
        })
        .collect();
    let outputs: Vec<SsaVar> = (n_inputs..n_inputs + 200).map(ssa).collect();
    let inputs: Vec<SsaVar> = (0..n_inputs).map(ssa).collect();
    body.push(plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs,
        inputs,
        program_bytes: vec![0xFF],
    }))));

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker
        .lower(body)
        .expect("wide-output WitnessCall with cold inputs must lower without a frame overflow");

    let classic_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCall { .. }))
        .count();
    let heap_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCallHeap { .. }))
        .count();
    // A genuine split forwards the hot live set as captures; the
    // trivial root entry is `InstantiateTemplate(0, [], [])` with
    // *empty* capture_regs, so filtering on a non-empty capture
    // set distinguishes a real `do_split` from the always-present
    // root and keeps this assertion non-vacuous.
    let split_count = program
        .body
        .iter()
        .filter(|i| {
            matches!(
                &i.opcode,
                lysis::Opcode::InstantiateTemplate { capture_regs, .. }
                    if !capture_regs.is_empty()
            )
        })
        .count();

    assert_eq!(
        classic_count, 0,
        "the cold-input-pressured call must not take the classic path"
    );
    assert_eq!(heap_count, 1, "it must take the always-fitting heap path");
    assert!(
        split_count >= 1,
        "the scenario must actually exercise a split (the call's \
             inputs must be spilled to make them cold); without a real \
             capture-forwarding split there are no cold inputs and the \
             pin would be vacuous"
    );
}
