use super::*;

#[test]
fn lowers_const_add_const() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(7),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(3),
        }),
        plain(Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    // Two Consts + one Add.
    assert_eq!(out.len(), 3);
    assert!(matches!(out[0], lysis::InstructionKind::Const { .. }));
    assert!(matches!(out[1], lysis::InstructionKind::Const { .. }));
    assert!(matches!(out[2], lysis::InstructionKind::Add { .. }));
}

#[test]
fn lowers_range_check_and_decompose() {
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::RangeCheck {
            result: ssa(0),
            operand: ssa(0),
            bits: 8,
        }),
        plain(Instruction::Decompose {
            result: ssa(0),
            bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
            operand: ssa(0),
            num_bits: 4,
        }),
    ];
    let out = run(&body);
    // Input + RangeCheck + Decompose = 3 instructions.
    assert_eq!(out.len(), 3);
    assert!(matches!(out[0], lysis::InstructionKind::Input { .. }));
    assert!(matches!(out[1], lysis::InstructionKind::RangeCheck { .. }));
    let bit_count = match &out[2] {
        lysis::InstructionKind::Decompose { bit_results, .. } => bit_results.len(),
        _ => panic!(),
    };
    assert_eq!(bit_count, 4);
}

#[test]
fn lowers_assert_eq_side_effect() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(5),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(5),
        }),
        plain(Instruction::AssertEq {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            message: None,
        }),
    ];
    let out = run(&body);
    let asserts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 1);
}

#[test]
fn lowers_loop_unroll_three_iterations() {
    // for i in 0..3: r_mul = i * i
    let body = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 3,
        body: vec![plain(Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        })],
    }];
    let out = run(&body);
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    let muls = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
        .count();
    assert_eq!(consts, 3, "one Const per iteration (iter_var)");
    assert_eq!(muls, 3, "three Muls, one per iteration");
}

#[test]
fn unfolds_symbolic_indexed_effect_per_iteration() {
    // Outer body sets up the slot wires + value source via real
    // Plain(Input) ops so the walker has them in `ssa_to_reg`
    // when the LoopUnroll body runs (mirrors the public-output
    // array case where slots are pre-emitted by scaffold).
    // SymbolicIndexedEffect(Let, [v_a, v_b, v_c], iter_var,
    // value_var) inside `for i in 0..3` should unroll into 3
    // AssertEqs, one per slot.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "slot_a".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "slot_b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(2),
            name: "slot_c".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(3),
            name: "value".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(4),
            start: 0,
            end: 3,
            body: vec![ExtendedInstruction::SymbolicIndexedEffect {
                kind: IndexedEffectKind::Let,
                array_slots: vec![ssa(0), ssa(1), ssa(2)],
                index_var: ssa(4),
                value_var: Some(ssa(3)),
                span: None,
            }],
        },
    ];
    let out = run(&body);

    // Inputs: 4 distinct names, all preserved.
    let inputs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
        .count();
    assert_eq!(inputs, 4, "4 named Inputs");

    // Consts: 3 distinct iter values (0, 1, 2). The InterningSink
    // dedupes equal values, but here all three are distinct.
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    assert_eq!(consts, 3, "one Const per iteration");

    // AssertEqs: 3 (one per iteration), never dedupe (side-effect).
    let asserts: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(asserts.len(), 3, "3 AssertEqs");
    // Each AssertEq's lhs should be the slot wire (Input result),
    // each rhs should be the value Input. Distinct lhs → 3 unique.
    let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
    assert_eq!(lhs_set.len(), 3, "3 distinct slot lhs");
    let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
    assert_eq!(rhs_set.len(), 1, "all 3 rhs point at the same value Input");
}

#[test]
fn unfolds_symbolic_indexed_effect_with_affine_index() {
    // Body: for i in 0..3 { array[i + 2] := value }
    // The index `i + 2` is computed inside the body via a Const(2)
    // + Add op; walker_const must pick it up so the slot resolves
    // to array_slots[2..=4]. Pre-allocate 5 slots to host idx 2..4.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "s0".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "s1".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(2),
            name: "s2".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(3),
            name: "s3".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(4),
            name: "s4".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(5),
            name: "value".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(6),
            start: 0,
            end: 3,
            body: vec![
                plain(Instruction::Const {
                    result: ssa(7),
                    value: fe(2),
                }),
                plain(Instruction::Add {
                    result: ssa(8),
                    lhs: ssa(6),
                    rhs: ssa(7),
                }),
                ExtendedInstruction::SymbolicIndexedEffect {
                    kind: IndexedEffectKind::Let,
                    array_slots: vec![ssa(0), ssa(1), ssa(2), ssa(3), ssa(4)],
                    index_var: ssa(8),
                    value_var: Some(ssa(5)),
                    span: None,
                },
            ],
        },
    ];
    let out = run(&body);

    // 3 AssertEqs, lhs picking up slot 2, 3, 4 (i + 2 for i in 0..3).
    let asserts: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(asserts.len(), 3, "3 AssertEqs");
    let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
    assert_eq!(lhs_set.len(), 3, "3 distinct slots picked (i+2 for i=0..3)");
}

#[test]
fn rejects_symbolic_indexed_effect_when_index_not_const_foldable() {
    // Index_var depends on an Input (runtime), not a loop-iter
    // const → walker can't resolve. Expect the dedicated error.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "slot".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "runtime_idx".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(2),
            name: "value".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(3),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicIndexedEffect {
                kind: IndexedEffectKind::Let,
                array_slots: vec![ssa(0)],
                index_var: ssa(1),
                value_var: Some(ssa(2)),
                span: None,
            }],
        },
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body.clone()).expect_err("should refuse");
    assert!(
        matches!(err, WalkError::SymbolicIndexedEffectNotEmittable),
        "got {err:?}"
    );
}

#[test]
fn unfolds_symbolic_array_read_per_iteration() {
    // Outer body pre-emits 3 slot Inputs + a sink-target Input.
    // Inside `for i in 0..3 { sink := arr[i] }` the read binds
    // result_var to slot_i's reg per iteration; the trailing
    // AssertEq materialises one constraint per iteration with
    // rhs pointing at the iteration-specific slot.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "slot_a".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "slot_b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(2),
            name: "slot_c".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(3),
            name: "sink_target".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(4),
            start: 0,
            end: 3,
            body: vec![
                ExtendedInstruction::SymbolicArrayRead {
                    result_var: ssa(5),
                    array_slots: vec![ssa(0), ssa(1), ssa(2)],
                    index_var: ssa(4),
                    span: None,
                },
                plain(Instruction::AssertEq {
                    result: ssa(6),
                    lhs: ssa(3),
                    rhs: ssa(5),
                    message: None,
                }),
            ],
        },
    ];
    let out = run(&body);

    // 4 named Inputs preserved.
    let inputs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
        .count();
    assert_eq!(inputs, 4);

    // 3 AssertEqs (one per iteration). Each rhs picks up a
    // different slot's reg because result_var rebinds per-iter.
    let asserts: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(asserts.len(), 3, "3 AssertEqs");
    let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
    assert_eq!(lhs_set.len(), 1, "all 3 lhs share the sink_target reg");
    let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
    assert_eq!(
        rhs_set.len(),
        3,
        "3 distinct slot rhs (rebind per iteration)"
    );
}

#[test]
fn unfolds_symbolic_array_read_with_affine_index() {
    // Body: for i in 0..3 { sink := arr[i + 2] }. Index is computed
    // inside the body via Const(2) + Add; walker_const tracks the
    // fold and the read picks slots 2..=4.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "s0".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "s1".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(2),
            name: "s2".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(3),
            name: "s3".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(4),
            name: "s4".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(5),
            name: "sink_target".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(6),
            start: 0,
            end: 3,
            body: vec![
                plain(Instruction::Const {
                    result: ssa(7),
                    value: fe(2),
                }),
                plain(Instruction::Add {
                    result: ssa(8),
                    lhs: ssa(6),
                    rhs: ssa(7),
                }),
                ExtendedInstruction::SymbolicArrayRead {
                    result_var: ssa(9),
                    array_slots: vec![ssa(0), ssa(1), ssa(2), ssa(3), ssa(4)],
                    index_var: ssa(8),
                    span: None,
                },
                plain(Instruction::AssertEq {
                    result: ssa(10),
                    lhs: ssa(5),
                    rhs: ssa(9),
                    message: None,
                }),
            ],
        },
    ];
    let out = run(&body);

    let asserts: Vec<_> = out
        .iter()
        .filter_map(|i| match i {
            lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(asserts.len(), 3, "3 AssertEqs");
    let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
    assert_eq!(rhs_set.len(), 3, "3 distinct slots picked (i+2 for i=0..3)");
}

#[test]
fn rejects_symbolic_array_read_when_index_not_const_foldable() {
    // Index_var depends on a runtime Input (not a loop-iter
    // const) — walker can't resolve. Expect the dedicated error.
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "slot".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Input {
            result: ssa(1),
            name: "runtime_idx".into(),
            visibility: IrVisibility::Witness,
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: ssa(2),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicArrayRead {
                result_var: ssa(3),
                array_slots: vec![ssa(0)],
                index_var: ssa(1),
                span: None,
            }],
        },
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body.clone()).expect_err("should refuse");
    assert!(
        matches!(err, WalkError::SymbolicArrayReadNotEmittable),
        "got {err:?}"
    );
}
