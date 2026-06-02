use std::collections::HashMap;

use super::fe;
use crate::eval::evaluate;
use crate::types::{Instruction, IrProgram, Visibility};
use memory::FieldElement;

// ================================================================
// Educational error message tests
// ================================================================

#[test]
fn error_div_by_zero_shows_variable_names() {
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    p.set_name(x, "x".into());
    let y = p.fresh_var();
    p.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    p.set_name(y, "y".into());
    let r = p.fresh_var();
    p.push(Instruction::Div {
        result: r,
        lhs: x,
        rhs: y,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".into(), fe(42));
    inputs.insert("y".into(), FieldElement::ZERO);

    let err = evaluate(&p, &inputs).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("'x'"), "should mention dividend name: {msg}");
    assert!(msg.contains("'y'"), "should mention divisor name: {msg}");
    assert!(msg.contains("which is 0"), "should explain zero: {msg}");
}

#[test]
fn error_assert_eq_shows_names_and_values() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: Visibility::Public,
    });
    p.set_name(a, "a".into());
    let b = p.fresh_var();
    p.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    p.set_name(b, "b".into());
    let r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: r,
        lhs: a,
        rhs: b,
        message: None,
    });

    let mut inputs = HashMap::new();
    inputs.insert("a".into(), fe(42));
    inputs.insert("b".into(), fe(99));

    let err = evaluate(&p, &inputs).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("'a'"), "should mention lhs name: {msg}");
    assert!(msg.contains("'b'"), "should mention rhs name: {msg}");
    assert!(msg.contains("42"), "should show lhs value: {msg}");
    assert!(msg.contains("99"), "should show rhs value: {msg}");
}

#[test]
fn error_range_check_shows_name_value_max() {
    let mut p = IrProgram::new();
    let x = p.fresh_var();
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    p.set_name(x, "x".into());
    let r = p.fresh_var();
    p.push(Instruction::RangeCheck {
        result: r,
        operand: x,
        bits: 8,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".into(), fe(300));

    let err = evaluate(&p, &inputs).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("'x'"), "should mention variable name: {msg}");
    assert!(msg.contains("300"), "should show the value: {msg}");
    assert!(msg.contains("255"), "should show max value: {msg}");
}

#[test]
fn error_mux_non_boolean_shows_name_and_value() {
    let mut p = IrProgram::new();
    let cond = p.fresh_var();
    p.push(Instruction::Input {
        result: cond,
        name: "cond".into(),
        visibility: Visibility::Witness,
    });
    p.set_name(cond, "cond".into());
    let t = p.fresh_var();
    p.push(Instruction::Const {
        result: t,
        value: fe(10),
    });
    let f = p.fresh_var();
    p.push(Instruction::Const {
        result: f,
        value: fe(20),
    });
    let r = p.fresh_var();
    p.push(Instruction::Mux {
        result: r,
        cond,
        if_true: t,
        if_false: f,
    });

    let mut inputs = HashMap::new();
    inputs.insert("cond".into(), fe(5));

    let err = evaluate(&p, &inputs).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("'cond'"),
        "should mention condition name: {msg}"
    );
    assert!(msg.contains("5"), "should show the value: {msg}");
    assert!(msg.contains("boolean"), "should mention boolean: {msg}");
}
