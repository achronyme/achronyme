use ir::passes::const_fold;
use ir::types::{Instruction, IrProgram};
use memory::FieldElement;

#[test]
fn const_fold_not_zero() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[1] {
        assert_eq!(*value, FieldElement::ONE, "!0 should be 1");
    } else {
        panic!("expected Const after folding Not(0)");
    }
}

#[test]
fn const_fold_not_one() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[1] {
        assert!(value.is_zero(), "!1 should be 0");
    } else {
        panic!("expected Const after folding Not(1)");
    }
}

#[test]
fn const_fold_and_short_circuit_zero() {
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
    p.push(Instruction::And {
        result: c,
        lhs: zero,
        rhs: x,
    });

    const_fold::constant_fold(&mut p);

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert!(value.is_zero(), "0 && x should fold to 0");
    } else {
        panic!("expected Const(0) for 0 && x");
    }
}

#[test]
fn const_fold_or_short_circuit_one() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::ONE, "1 || x should fold to 1");
    } else {
        panic!("expected Const(1) for 1 || x");
    }
}

#[test]
fn const_fold_is_eq_same() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::ONE, "42 == 42 should be 1");
    } else {
        panic!("expected Const(1) for 42 == 42");
    }
}

#[test]
fn const_fold_is_eq_different() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert!(value.is_zero(), "42 == 99 should be 0");
    } else {
        panic!("expected Const(0) for 42 == 99");
    }
}

#[test]
fn const_fold_is_neq() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::ONE, "5 != 10 should be 1");
    } else {
        panic!("expected Const(1) for 5 != 10");
    }
}

#[test]
fn const_fold_and_both_true() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert_eq!(*value, FieldElement::ONE, "1 && 1 should be 1");
    } else {
        panic!("expected Const(1) for 1 && 1");
    }
}

#[test]
fn const_fold_or_both_false() {
    let mut p: IrProgram = IrProgram::new();
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

    if let Instruction::Const { value, .. } = &p.instructions()[2] {
        assert!(value.is_zero(), "0 || 0 should be 0");
    } else {
        panic!("expected Const(0) for 0 || 0");
    }
}

// ============================================================================
// DCE — New operators (conservative)
// ============================================================================
