use ir::passes::{const_fold, dce};
use ir::types::{Instruction, IrProgram};
use memory::FieldElement;

// ============================================================================
// Constant Folding
// ============================================================================

#[test]
fn const_fold_add() {
    let mut p = IrProgram::new();
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
    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::from_u64(10));
    } else {
        panic!("expected Const after folding, got {:?}", p.instructions[2]);
    }
}

#[test]
fn const_fold_sub() {
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::from_u64(7));
    } else {
        panic!("expected Const after folding");
    }
}

#[test]
fn const_fold_mul() {
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::from_u64(42));
    } else {
        panic!("expected Const after folding");
    }
}

#[test]
fn const_fold_mul_by_zero() {
    let mut p = IrProgram::new();
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
    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert!(value.is_zero());
    } else {
        panic!("expected Const(0) for x * 0");
    }
}

#[test]
fn const_fold_neg() {
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[1] {
        assert_eq!(*value, FieldElement::from_u64(5).neg());
    } else {
        panic!("expected Const after folding Neg");
    }
}

#[test]
fn const_fold_chain() {
    // 2 + 3 = 5, then 5 * 4 = 20
    let mut p = IrProgram::new();
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
    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::from_u64(5));
    } else {
        panic!("expected Const(5)");
    }
    if let Instruction::Const { value, .. } = &p.instructions[4] {
        assert_eq!(*value, FieldElement::from_u64(20));
    } else {
        panic!("expected Const(20)");
    }
}

#[test]
fn const_fold_no_fold_on_variable() {
    // x + 3 should NOT be folded
    let mut p = IrProgram::new();
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
    assert!(matches!(p.instructions[2], Instruction::Add { .. }));
}

#[test]
fn const_fold_div_zero_numerator() {
    // 0 / x → 0 (even if x is not constant)
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert!(value.is_zero(), "0/x should fold to 0");
    } else {
        panic!("expected Const(0) for 0/x");
    }
}

#[test]
fn const_fold_mux_true() {
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[3] {
        assert_eq!(*value, FieldElement::from_u64(42));
    } else {
        panic!("expected Const(42) for mux(1, 42, 99)");
    }
}

#[test]
fn const_fold_mux_false() {
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[3] {
        assert_eq!(*value, FieldElement::from_u64(99));
    } else {
        panic!("expected Const(99) for mux(0, 42, 99)");
    }
}

// ============================================================================
// Dead Code Elimination
// ============================================================================

#[test]
fn dce_removes_unused_const() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    // `a` is never used by anything

    let before = p.instructions.len();
    dce::dead_code_elimination(&mut p);

    assert!(
        p.instructions.len() < before,
        "DCE should remove unused Const"
    );
}

#[test]
fn dce_removes_unused_add() {
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let y = p.fresh_var();
    p.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: ir::Visibility::Witness,
    });
    // Unused add
    let _z = p.fresh_var();
    p.push(Instruction::Add {
        result: _z,
        lhs: x,
        rhs: y,
    });

    dce::dead_code_elimination(&mut p);

    // Add should be removed, inputs kept (side effects)
    assert_eq!(p.instructions.len(), 2);
}

#[test]
fn dce_keeps_used_const() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(42),
    });
    // `a` and `b` are used by AssertEq
    let c = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: c,
        lhs: a,
        rhs: b,
    });

    let before = p.instructions.len();
    dce::dead_code_elimination(&mut p);

    assert_eq!(
        p.instructions.len(),
        before,
        "DCE should not remove used Const or AssertEq"
    );
}

#[test]
fn dce_keeps_assert_eq() {
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    // AssertEq has side effects — never removed
    let c = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: c,
        lhs: x,
        rhs: x,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(p.instructions.len(), 2);
}

#[test]
fn dce_eliminates_unused_mul() {
    // Unused Mul is eliminated by DCE (only Input survives as side-effect)
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let _m = p.fresh_var();
    p.push(Instruction::Mul {
        result: _m,
        lhs: x,
        rhs: x,
    });

    dce::dead_code_elimination(&mut p);

    // Mul is eliminated (unused result), only Input survives
    assert_eq!(p.instructions.len(), 1);
}

// ============================================================================
// Combined: fold + DCE
// ============================================================================

#[test]
fn optimize_full_pipeline() {
    use ir::passes::optimize;

    let mut p = IrProgram::new();
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
    // Unused add: 2 + 3 = 5 (will fold, then DCE removes)
    let c = p.fresh_var();
    p.push(Instruction::Add {
        result: c,
        lhs: a,
        rhs: b,
    });

    let before = p.instructions.len();
    optimize(&mut p);

    // After fold: 3 Consts. After DCE: all removed (none used).
    assert!(
        p.instructions.len() < before,
        "optimize should reduce instruction count"
    );
    assert_eq!(
        p.instructions.len(),
        0,
        "all unused consts should be removed"
    );
}

#[test]
fn dce_chain_fixpoint() {
    // Chain: Const(a) → Add(b, a, a) → Neg(c, b) → nothing uses c
    // Single-pass DCE would remove Neg (c unused), but leave Add (b was "used" by Neg).
    // Fixpoint DCE should remove all three.
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(1),
    });
    let b = p.fresh_var();
    p.push(Instruction::Add {
        result: b,
        lhs: a,
        rhs: a,
    });
    let c = p.fresh_var();
    p.push(Instruction::Neg {
        result: c,
        operand: b,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(
        p.instructions.len(),
        0,
        "fixpoint DCE should remove entire dead chain"
    );
}

#[test]
fn dce_chain_partial_live() {
    // Chain: Const(a) → Add(b, a, a) → Sub(c, b, a) → AssertEq uses c
    // Nothing should be removed — the whole chain feeds into a side-effect.
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(1),
    });
    let b = p.fresh_var();
    p.push(Instruction::Add {
        result: b,
        lhs: a,
        rhs: a,
    });
    let c = p.fresh_var();
    p.push(Instruction::Sub {
        result: c,
        lhs: b,
        rhs: a,
    });
    let d = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: d,
        lhs: c,
        rhs: a,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(
        p.instructions.len(),
        4,
        "nothing should be removed when chain feeds into AssertEq"
    );
}

// ============================================================================
// Constant Folding — New operators
// ============================================================================

#[test]
fn const_fold_not_zero() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ZERO,
    });
    let b = p.fresh_var();
    p.push(Instruction::Not {
        result: b,
        operand: a,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[1] {
        assert_eq!(*value, FieldElement::ONE, "!0 should be 1");
    } else {
        panic!("expected Const after folding Not(0)");
    }
}

#[test]
fn const_fold_not_one() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    let b = p.fresh_var();
    p.push(Instruction::Not {
        result: b,
        operand: a,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[1] {
        assert!(value.is_zero(), "!1 should be 0");
    } else {
        panic!("expected Const after folding Not(1)");
    }
}

#[test]
fn const_fold_and_short_circuit_zero() {
    let mut p = IrProgram::new();
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
    p.push(Instruction::And {
        result: c,
        lhs: zero,
        rhs: x,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert!(value.is_zero(), "0 && x should fold to 0");
    } else {
        panic!("expected Const(0) for 0 && x");
    }
}

#[test]
fn const_fold_or_short_circuit_one() {
    let mut p = IrProgram::new();
    let one = p.fresh_var();
    p.push(Instruction::Const {
        result: one,
        value: FieldElement::ONE,
    });
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let c = p.fresh_var();
    p.push(Instruction::Or {
        result: c,
        lhs: one,
        rhs: x,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::ONE, "1 || x should fold to 1");
    } else {
        panic!("expected Const(1) for 1 || x");
    }
}

#[test]
fn const_fold_is_eq_same() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(42),
    });
    let c = p.fresh_var();
    p.push(Instruction::IsEq {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::ONE, "42 == 42 should be 1");
    } else {
        panic!("expected Const(1) for 42 == 42");
    }
}

#[test]
fn const_fold_is_eq_different() {
    let mut p = IrProgram::new();
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
    p.push(Instruction::IsEq {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert!(value.is_zero(), "42 == 99 should be 0");
    } else {
        panic!("expected Const(0) for 42 == 99");
    }
}

#[test]
fn const_fold_is_neq() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(5),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(10),
    });
    let c = p.fresh_var();
    p.push(Instruction::IsNeq {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::ONE, "5 != 10 should be 1");
    } else {
        panic!("expected Const(1) for 5 != 10");
    }
}

#[test]
fn const_fold_and_both_true() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::ONE,
    });
    let c = p.fresh_var();
    p.push(Instruction::And {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert_eq!(*value, FieldElement::ONE, "1 && 1 should be 1");
    } else {
        panic!("expected Const(1) for 1 && 1");
    }
}

#[test]
fn const_fold_or_both_false() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ZERO,
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::ZERO,
    });
    let c = p.fresh_var();
    p.push(Instruction::Or {
        result: c,
        lhs: a,
        rhs: b,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions[2] {
        assert!(value.is_zero(), "0 || 0 should be 0");
    } else {
        panic!("expected Const(0) for 0 || 0");
    }
}

// ============================================================================
// DCE — New operators (conservative)
// ============================================================================

#[test]
fn dce_keeps_assert() {
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let a = p.fresh_var();
    p.push(Instruction::Assert {
        result: a,
        operand: x,
    });

    dce::dead_code_elimination(&mut p);

    // Assert has side effects — never removed
    assert_eq!(p.instructions.len(), 2);
}

// ============================================================================
// M8: Sub-self and Div-self folding
// ============================================================================

#[test]
fn const_fold_sub_self_is_zero() {
    // Input(w) → Sub(w, w) → should fold to Const(0)
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[1] {
        assert_eq!(*value, FieldElement::ZERO);
    } else {
        panic!(
            "expected Const(0) after folding Sub(w,w), got {:?}",
            p.instructions[1]
        );
    }
}

#[test]
fn const_fold_div_self_constant_is_one() {
    // Const(5) → Div(c, c) → should fold to Const(1)
    let mut p = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions[1] {
        assert_eq!(*value, FieldElement::ONE);
    } else {
        panic!(
            "expected Const(1) after folding Div(c,c), got {:?}",
            p.instructions[1]
        );
    }
}

#[test]
fn const_fold_div_self_witness_not_folded() {
    // Input(w) → Div(w, w) → should NOT fold (preserve w != 0 enforcement)
    let mut p = IrProgram::new();
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
        matches!(&p.instructions[1], Instruction::Div { .. }),
        "Div(w,w) for witness should NOT be folded, got {:?}",
        p.instructions[1]
    );
}
