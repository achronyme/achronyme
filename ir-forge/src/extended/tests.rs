use memory::{Bn254Fr, FieldElement};

use ir_core::Visibility;

use super::*;

fn ssa(i: u32) -> SsaVar {
    SsaVar(i.into())
}

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

#[test]
fn plain_round_trips_instruction() {
    let inst = Instruction::<Bn254Fr>::Add {
        result: ssa(3),
        lhs: ssa(1),
        rhs: ssa(2),
    };
    let ext = ExtendedInstruction::Plain(inst.clone());
    assert!(ext.is_plain());
    assert!(matches!(ext.as_plain(), Some(Instruction::Add { .. })));
}

#[test]
fn extended_instruction_size_stays_plain_sized() {
    assert_eq!(std::mem::size_of::<Instruction<Bn254Fr>>(), 56);
    assert_eq!(std::mem::size_of::<ExtendedInstruction<Bn254Fr>>(), 64);
}

#[test]
fn template_body_holds_nested_extended_instructions() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::Plain(Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }),
        ExtendedInstruction::Plain(Instruction::Add {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }),
    ];
    let t = ExtendedInstruction::<Bn254Fr>::TemplateBody {
        id: TemplateId(7),
        frame_size: 16,
        n_params: 2,
        captures: vec![ssa(50), ssa(51)],
        body,
    };
    assert!(!t.is_plain());
    assert!(t.as_plain().is_none());
}

#[test]
fn template_call_captures_and_outputs() {
    let call = ExtendedInstruction::<Bn254Fr>::TemplateCall {
        template_id: TemplateId(7),
        captures: vec![ssa(1), ssa(2)],
        outputs: vec![ssa(10), ssa(11)],
    };
    match call {
        ExtendedInstruction::TemplateCall {
            template_id,
            captures,
            outputs,
        } => {
            assert_eq!(template_id, TemplateId(7));
            assert_eq!(captures.len(), 2);
            assert_eq!(outputs.len(), 2);
        }
        _ => panic!("expected TemplateCall"),
    }
}

#[test]
fn loop_unroll_nests_body() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> =
        vec![ExtendedInstruction::Plain(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Witness,
        })];
    let loop_node = ExtendedInstruction::<Bn254Fr>::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 4,
        body,
    };
    assert!(!loop_node.is_plain());
}

#[test]
fn template_id_displays_with_t_prefix() {
    assert_eq!(format!("{}", TemplateId(42)), "T42");
}

#[test]
fn symbolic_indexed_effect_let_carries_resolved_array_slots() {
    let effect = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
        kind: IndexedEffectKind::Let,
        array_slots: vec![ssa(10), ssa(11), ssa(12), ssa(13)],
        index_var: ssa(20),
        value_var: Some(ssa(30)),
        span: None,
    };
    assert!(!effect.is_plain());
    assert!(effect.as_plain().is_none());
    match effect {
        ExtendedInstruction::SymbolicIndexedEffect {
            kind,
            array_slots,
            index_var,
            value_var,
            ..
        } => {
            assert_eq!(kind, IndexedEffectKind::Let);
            assert_eq!(array_slots.len(), 4);
            assert_eq!(index_var, ssa(20));
            assert_eq!(value_var, Some(ssa(30)));
        }
        _ => panic!("expected SymbolicIndexedEffect"),
    }
}

#[test]
fn symbolic_indexed_effect_witness_hint_omits_value() {
    let effect = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
        kind: IndexedEffectKind::WitnessHint,
        array_slots: vec![ssa(0), ssa(1)],
        index_var: ssa(5),
        value_var: None,
        span: None,
    };
    match effect {
        ExtendedInstruction::SymbolicIndexedEffect {
            kind, value_var, ..
        } => {
            assert_eq!(kind, IndexedEffectKind::WitnessHint);
            assert!(value_var.is_none());
        }
        _ => panic!("expected SymbolicIndexedEffect"),
    }
}

#[test]
fn symbolic_array_read_carries_result_and_slots() {
    let read = ExtendedInstruction::<Bn254Fr>::SymbolicArrayRead {
        result_var: ssa(40),
        array_slots: vec![ssa(10), ssa(11), ssa(12), ssa(13)],
        index_var: ssa(20),
        span: None,
    };
    assert!(!read.is_plain());
    assert!(read.as_plain().is_none());
    match read {
        ExtendedInstruction::SymbolicArrayRead {
            result_var,
            array_slots,
            index_var,
            ..
        } => {
            assert_eq!(result_var, ssa(40));
            assert_eq!(array_slots.len(), 4);
            assert_eq!(index_var, ssa(20));
        }
        _ => panic!("expected SymbolicArrayRead"),
    }
}

#[test]
fn symbolic_array_read_distinct_from_indexed_effect() {
    let read = ExtendedInstruction::<Bn254Fr>::SymbolicArrayRead {
        result_var: ssa(0),
        array_slots: vec![ssa(1)],
        index_var: ssa(2),
        span: None,
    };
    let write = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
        kind: IndexedEffectKind::Let,
        array_slots: vec![ssa(1)],
        index_var: ssa(2),
        value_var: Some(ssa(3)),
        span: None,
    };
    // Sanity: the two variants don't accidentally pattern-match the
    // same tag, so downstream exhaustive matches stay exhaustive.
    assert!(matches!(
        read,
        ExtendedInstruction::SymbolicArrayRead { .. }
    ));
    assert!(matches!(
        write,
        ExtendedInstruction::SymbolicIndexedEffect { .. }
    ));
}

#[test]
fn symbolic_shift_carries_operand_amount_and_width() {
    let shift = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(20),
        num_bits: 32,
        direction: ShiftDirection::Right,
        span: None,
    };
    assert!(!shift.is_plain());
    assert!(shift.as_plain().is_none());
    match shift {
        ExtendedInstruction::SymbolicShift {
            result_var,
            operand_var,
            shift_var,
            num_bits,
            direction,
            ..
        } => {
            assert_eq!(result_var, ssa(50));
            assert_eq!(operand_var, ssa(10));
            assert_eq!(shift_var, ssa(20));
            assert_eq!(num_bits, 32);
            assert_eq!(direction, ShiftDirection::Right);
        }
        _ => panic!("expected SymbolicShift"),
    }
}

#[test]
fn symbolic_shift_left_distinct_from_right() {
    let l = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
        result_var: ssa(0),
        operand_var: ssa(1),
        shift_var: ssa(2),
        num_bits: 8,
        direction: ShiftDirection::Left,
        span: None,
    };
    let r = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
        result_var: ssa(0),
        operand_var: ssa(1),
        shift_var: ssa(2),
        num_bits: 8,
        direction: ShiftDirection::Right,
        span: None,
    };
    // Discriminator differs even with otherwise-identical fields.
    match (&l, &r) {
        (
            ExtendedInstruction::SymbolicShift { direction: dl, .. },
            ExtendedInstruction::SymbolicShift { direction: dr, .. },
        ) => assert_ne!(dl, dr),
        _ => panic!("expected two SymbolicShift"),
    }
}

#[test]
fn indexed_effect_kind_distinguishes_let_from_witness_hint() {
    // Sanity check: the discriminator stays a small Copy enum so
    // it can be embedded in match arms without lifetime gymnastics.
    let a = IndexedEffectKind::Let;
    let b = IndexedEffectKind::WitnessHint;
    assert_ne!(a, b);
    let c = a; // Copy
    assert_eq!(a, c);
}

#[test]
fn from_instruction_wraps_as_plain() {
    let inst = Instruction::<Bn254Fr>::Const {
        result: ssa(0),
        value: fe(5),
    };
    let ext: ExtendedInstruction<Bn254Fr> = inst.into();
    assert!(ext.is_plain());
}

#[test]
fn vec_map_into_works() {
    // The migration pattern: push `inst.into()` or run
    // `instrs.into_iter().map(Into::into)` on an existing Vec.
    let input: Vec<Instruction<Bn254Fr>> = vec![
        Instruction::Const {
            result: ssa(0),
            value: fe(1),
        },
        Instruction::Add {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        },
    ];
    let output: Vec<ExtendedInstruction<Bn254Fr>> = input.into_iter().map(Into::into).collect();
    assert_eq!(output.len(), 2);
    assert!(output.iter().all(|e| e.is_plain()));
}

#[test]
fn into_plain_round_trips_when_plain() {
    let inst = Instruction::<Bn254Fr>::Mul {
        result: ssa(3),
        lhs: ssa(1),
        rhs: ssa(2),
    };
    let ext: ExtendedInstruction<Bn254Fr> = inst.clone().into();
    let back = ext.into_plain().expect("plain variant");
    match back {
        Instruction::Mul { result, lhs, rhs } => {
            assert_eq!(result, ssa(3));
            assert_eq!(lhs, ssa(1));
            assert_eq!(rhs, ssa(2));
        }
        _ => panic!("expected Mul"),
    }
}

#[test]
fn into_plain_returns_err_for_non_plain() {
    let call = ExtendedInstruction::<Bn254Fr>::TemplateCall {
        template_id: TemplateId(0),
        captures: vec![],
        outputs: vec![],
    };
    let err = call.into_plain().expect_err("non-plain variant");
    assert!(matches!(err, ExtendedInstruction::TemplateCall { .. }));
}
