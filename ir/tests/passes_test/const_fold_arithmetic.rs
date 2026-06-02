use ir::passes::const_fold;
use ir::types::{Instruction, IrProgram};
use memory::FieldElement;

// ============================================================================
// Constant Folding
// ============================================================================

#[test]
fn const_fold_add() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(3),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(7),
    });
    let c = p.fresh_var();
    p.push(Instruction::Add {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    // Add should be replaced by Const(10)
    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::from_u64(10));
    } else {
        panic!(
            "expected Const after folding, got {:?}",
            p.instructions()[2]
        );
    }
}

#[test]
fn const_fold_sub() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(10),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(3),
    });
    let c = p.fresh_var();
    p.push(Instruction::Sub {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::from_u64(7));
    } else {
        panic!("expected Const after folding");
    }
}

#[test]
fn const_fold_mul() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(6),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(7),
    });
    let c = p.fresh_var();
    p.push(Instruction::Mul {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::from_u64(42));
    } else {
        panic!("expected Const after folding");
    }
}

#[test]
fn const_fold_mul_by_zero() {
    let mut p: IrProgram = IrProgram::new();
    // x is a non-constant Input
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let zero = p.fresh_var();
    p.push(Instruction::Const {
        result: zero,
        value: FieldElement::ZERO,
    });
    let c = p.fresh_var();
    p.push(Instruction::Mul {
        result: c,
        lhs: x,
        rhs: zero,
    });

    const_fold::constant_fold(&mut p);

    // x * 0 should fold to Const(0)
    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert!(value.is_zero());
    } else {
        panic!("expected Const(0) for x * 0");
    }
}

#[test]
fn const_fold_neg() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(5),
    });
    let b = p.fresh_var();
    p.push(Instruction::Neg {
        result: b,
        operand: a,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[1] {
        assert_eq!(*value, FieldElement::from_u64(5).neg());
    } else {
        panic!("expected Const after folding Neg");
    }
}

#[test]
fn const_fold_chain() {
    // 2 + 3 = 5, then 5 * 4 = 20
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(2),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(3),
    });
    let c = p.fresh_var();
    p.push(Instruction::Add {
        result: c,
        lhs: a,
        rhs: b,
    });
    let d = p.fresh_var();
    p.push(Instruction::Const {
        result: d,
        value: FieldElement::from_u64(4),
    });
    let e = p.fresh_var();
    p.push(Instruction::Mul {
        result: e,
        lhs: c,
        rhs: d,
    });

    const_fold::constant_fold(&mut p);

    // c should be Const(5), e should be Const(20)
    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::from_u64(5));
    } else {
        panic!("expected Const(5)");
    }
    if let Instruction::Const { value, .. } = &p.instructions()[4] {
        assert_eq!(*value, FieldElement::from_u64(20));
    } else {
        panic!("expected Const(20)");
    }
}

#[test]
fn const_fold_no_fold_on_variable() {
    // x + 3 should NOT be folded
    let mut p: IrProgram = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let three = p.fresh_var();
    p.push(Instruction::Const {
        result: three,
        value: FieldElement::from_u64(3),
    });
    let c = p.fresh_var();
    p.push(Instruction::Add {
        result: c,
        lhs: x,
        rhs: three,
    });

    const_fold::constant_fold(&mut p);

    // Should still be an Add
    assert!(matches!(p.instructions()[2], Instruction::Add { .. }));
}

#[test]
fn const_fold_div_zero_numerator() {
    // 0 / x → 0 (even if x is not constant)
    let mut p: IrProgram = IrProgram::new();
    let zero = p.fresh_var();
    p.push(Instruction::Const {
        result: zero,
        value: FieldElement::ZERO,
    });
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let c = p.fresh_var();
    p.push(Instruction::Div {
        result: c,
        lhs: zero,
        rhs: x,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert!(value.is_zero(), "0/x should fold to 0");
    } else {
        panic!("expected Const(0) for 0/x");
    }
}

#[test]
fn const_fold_mux_true() {
    let mut p: IrProgram = IrProgram::new();
    let one = p.fresh_var();
    p.push(Instruction::Const {
        result: one,
        value: FieldElement::ONE,
    });
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(99),
    });
    let c = p.fresh_var();
    p.push(Instruction::Mux {
        result: c,
        cond: one,
        if_true: a,
        if_false: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[3] {
        assert_eq!(*value, FieldElement::from_u64(42));
    } else {
        panic!("expected Const(42) for mux(1, 42, 99)");
    }
}

#[test]
fn const_fold_mux_false() {
    let mut p: IrProgram = IrProgram::new();
    let zero = p.fresh_var();
    p.push(Instruction::Const {
        result: zero,
        value: FieldElement::ZERO,
    });
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(99),
    });
    let c = p.fresh_var();
    p.push(Instruction::Mux {
        result: c,
        cond: zero,
        if_true: a,
        if_false: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[3] {
        assert_eq!(*value, FieldElement::from_u64(99));
    } else {
        panic!("expected Const(99) for mux(0, 42, 99)");
    }
}

// ============================================================================
// Dead Code Elimination
// ============================================================================

#[test]
fn const_fold_sub_self_is_zero() {
    // Input(w) → Sub(w, w) → should fold to Const(0)
    let mut p: IrProgram = IrProgram::new();
    let w = p.fresh_var();
    p.push(Instruction::Input {
        result: w,
        name: "w".into(),
        visibility: ir::Visibility::Witness,
    });
    let r = p.fresh_var();
    p.push(Instruction::Sub {
        result: r,
        lhs: w,
        rhs: w,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[1] {
        assert_eq!(*value, FieldElement::ZERO);
    } else {
        panic!(
            "expected Const(0) after folding Sub(w,w), got {:?}",
            p.instructions()[1]
        );
    }
}

#[test]
fn const_fold_div_self_constant_is_one() {
    // Const(5) → Div(c, c) → should fold to Const(1)
    let mut p: IrProgram = IrProgram::new();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: c,
        value: FieldElement::from_u64(5),
    });
    let r = p.fresh_var();
    p.push(Instruction::Div {
        result: r,
        lhs: c,
        rhs: c,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[1] {
        assert_eq!(*value, FieldElement::ONE);
    } else {
        panic!(
            "expected Const(1) after folding Div(c,c), got {:?}",
            p.instructions()[1]
        );
    }
}

#[test]
fn const_fold_div_self_witness_not_folded() {
    // Input(w) → Div(w, w) → should NOT fold (preserve w != 0 enforcement)
    let mut p: IrProgram = IrProgram::new();
    let w = p.fresh_var();
    p.push(Instruction::Input {
        result: w,
        name: "w".into(),
        visibility: ir::Visibility::Witness,
    });
    let r = p.fresh_var();
    p.push(Instruction::Div {
        result: r,
        lhs: w,
        rhs: w,
    });

    const_fold::constant_fold(&mut p);

    assert!(
        matches!(&p.instructions()[1], Instruction::Div { .. }),
        "Div(w,w) for witness should NOT be folded, got {:?}",
        p.instructions()[1]
    );
}
