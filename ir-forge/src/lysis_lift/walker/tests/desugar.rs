use super::*;

#[test]
fn refuses_negative_loop_bound() {
    let body = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: -1,
        end: 2,
        body: vec![],
    }];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let err = walker.lower(body.clone()).expect_err("should refuse");
    assert!(matches!(err, WalkError::NegativeLoopBound { .. }));
}

#[test]
fn desugars_not_to_sub_with_one() {
    // Not(x) = 1 - x. Expect: LoadConst(1), Input(x), Sub(one, x).
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Not {
            result: ssa(1),
            operand: ssa(0),
        }),
    ];
    let out = run(&body);
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(consts, 1, "one pre-allocated Const for `one`");
    assert_eq!(subs, 1, "Not desugars to one Sub");
}

#[test]
fn desugars_and_to_mul() {
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
        plain(Instruction::And {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    // And does NOT need `one` — no extra Const emitted.
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    let muls = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
        .count();
    assert_eq!(consts, 0, "no one-const needed when only And is used");
    assert_eq!(muls, 1, "And desugars to one Mul");
}

#[test]
fn desugars_or_to_add_mul_sub() {
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
        plain(Instruction::Or {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    let adds = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Add { .. }))
        .count();
    let muls = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(adds, 1);
    assert_eq!(muls, 1);
    assert_eq!(subs, 1);
}

#[test]
fn desugars_assert_to_assert_eq_with_one() {
    let body = vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "b".into(),
            visibility: IrVisibility::Witness,
        }),
        plain(Instruction::Assert {
            result: ssa(1),
            operand: ssa(0),
            message: None,
        }),
    ];
    let out = run(&body);
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    let asserts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
        .count();
    assert_eq!(consts, 1, "one pre-allocated Const for `one`");
    assert_eq!(asserts, 1, "Assert(x) desugars to AssertEq(x, one)");
}

#[test]
fn desugars_not_inside_loop_body() {
    // The `one` Const is emitted ABOVE the loop so body_byte_size
    // stays correct. Use iter bounds that avoid collision with 1
    // (which would get hash-cons deduped against `one`): 3..6.
    let body = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 3,
        end: 6,
        body: vec![plain(Instruction::Not {
            result: ssa(1),
            operand: ssa(0),
        })],
    }];
    let out = run(&body);
    // Expect: 1 one-const + 3 distinct iter consts (3, 4, 5) + 3 Subs.
    let consts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(consts, 4, "one + 3 distinct iter vars");
    assert_eq!(subs, 3, "Not per iteration");
}

#[test]
fn desugars_is_neq_to_is_eq_plus_sub() {
    // IsNeq(x,y) = 1 - IsEq(x,y).
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
        plain(Instruction::IsNeq {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    let eqs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IsEq { .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(eqs, 1);
    assert_eq!(subs, 1);
}

#[test]
fn desugars_is_le_to_is_lt_reversed_plus_sub() {
    // IsLe(x,y) = 1 - IsLt(y, x).
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
        plain(Instruction::IsLe {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let out = run(&body);
    let lts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IsLt { .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(lts, 1);
    assert_eq!(subs, 1);
}

#[test]
fn preserves_is_lt_bounded_bitwidth_hint() {
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
        plain(Instruction::IsLtBounded {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            bitwidth: 16,
        }),
    ];
    let out = run(&body);
    let lts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IsLtBounded { bitwidth: 16, .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(lts, 1);
    assert_eq!(subs, 0);
}

#[test]
fn desugars_is_le_bounded_like_is_le() {
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
        plain(Instruction::IsLeBounded {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            bitwidth: 8,
        }),
    ];
    let out = run(&body);
    let lts = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::IsLtBounded { bitwidth: 8, .. }))
        .count();
    let subs = out
        .iter()
        .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
        .count();
    assert_eq!(lts, 1);
    assert_eq!(subs, 1);
}
