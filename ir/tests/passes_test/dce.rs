use ir::passes::dce;
use ir::types::{Instruction, IrProgram};
use memory::FieldElement;

#[test]
fn dce_removes_unused_const() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(42),
    });
    // `a` is never used by anything

    let before = p.len();
    dce::dead_code_elimination(&mut p);

    assert!(p.len() < before, "DCE should remove unused Const");
}

#[test]
fn dce_removes_unused_add() {
    let mut p: IrProgram = IrProgram::new();
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
    assert_eq!(p.len(), 2);
}

#[test]
fn dce_keeps_used_const() {
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
    // `a` and `b` are used by AssertEq
    let c = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: c,
        lhs: a,
        rhs: b,
        message: None,
    });

    let before = p.len();
    dce::dead_code_elimination(&mut p);

    assert_eq!(
        p.len(),
        before,
        "DCE should not remove used Const or AssertEq"
    );
}

#[test]
fn dce_keeps_assert_eq() {
    let mut p: IrProgram = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    let y = p.fresh_var();
    p.push(Instruction::Const {
        result: y,
        value: FieldElement::from_u64(0),
    });
    // Non-tautological AssertEq has side effects — never removed
    let c = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: c,
        lhs: x,
        rhs: y,
        message: None,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(p.len(), 3);
}

#[test]
fn dce_eliminates_tautological_assert_eq() {
    let mut p: IrProgram = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: ir::Visibility::Witness,
    });
    // Tautological AssertEq(x, x) carries zero information — removed
    let c = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: c,
        lhs: x,
        rhs: x,
        message: None,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(p.len(), 1);
}

#[test]
fn dce_eliminates_unused_mul() {
    // Unused Mul is eliminated by DCE (only Input survives as side-effect)
    let mut p: IrProgram = IrProgram::new();
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
    assert_eq!(p.len(), 1);
}

// ============================================================================
// Combined: fold + DCE
// ============================================================================

#[test]
fn dce_chain_fixpoint() {
    // Chain: Const(a) → Add(b, a, a) → Neg(c, b) → nothing uses c
    // Single-pass DCE would remove Neg (c unused), but leave Add (b was "used" by Neg).
    // Fixpoint DCE should remove all three.
    let mut p: IrProgram = IrProgram::new();
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

    assert_eq!(p.len(), 0, "fixpoint DCE should remove entire dead chain");
}

#[test]
fn dce_chain_partial_live() {
    // Chain: Const(a) → Add(b, a, a) → Sub(c, b, a) → AssertEq uses c
    // Nothing should be removed — the whole chain feeds into a side-effect.
    let mut p: IrProgram = IrProgram::new();
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
        message: None,
    });

    dce::dead_code_elimination(&mut p);

    assert_eq!(
        p.len(),
        4,
        "nothing should be removed when chain feeds into AssertEq"
    );
}

// ============================================================================
// Constant Folding — New operators
// ============================================================================

#[test]
fn dce_keeps_assert() {
    let mut p: IrProgram = IrProgram::new();
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
        message: None,
    });

    dce::dead_code_elimination(&mut p);

    // Assert has side effects — never removed
    assert_eq!(p.len(), 2);
}

// ============================================================================
// M8: Sub-self and Div-self folding
// ============================================================================
