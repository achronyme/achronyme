use super::{empty_inputs, fe};
use crate::eval::{evaluate, EvalError};
use crate::types::{Instruction, IrProgram};
use memory::FieldElement;

#[test]
fn eval_assert_ok() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    p.push(Instruction::Assert {
        result: r,
        operand: a,
        message: None,
    });
    assert!(evaluate(&p, &empty_inputs()).is_ok());
}

#[test]
fn eval_assert_fail() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::Assert {
        result: r,
        operand: a,
        message: None,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::AssertionFailed { .. }));
}

#[test]
fn eval_assert_fail_with_message() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::Assert {
        result: r,
        operand: a,
        message: Some("eligibility check failed".into()),
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("eligibility check failed"),
        "expected custom message in error, got: {msg}"
    );
}

#[test]
fn eval_assert_eq_fail() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(1),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(2),
    });
    p.push(Instruction::AssertEq {
        result: r,
        lhs: a,
        rhs: b,
        message: None,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::AssertEqFailed { .. }));
}

#[test]
fn eval_assert_eq_fail_with_message() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(1),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(2),
    });
    p.push(Instruction::AssertEq {
        result: r,
        lhs: a,
        rhs: b,
        message: Some("commitment mismatch".into()),
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("commitment mismatch"),
        "expected custom message in error, got: {msg}"
    );
}

#[test]
fn eval_range_check_ok() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(255),
    });
    p.push(Instruction::RangeCheck {
        result: r,
        operand: a,
        bits: 8,
    });
    assert!(evaluate(&p, &empty_inputs()).is_ok());
}

#[test]
fn eval_range_check_fail() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(256),
    });
    p.push(Instruction::RangeCheck {
        result: r,
        operand: a,
        bits: 8,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::RangeCheckFailed { .. }));
}
