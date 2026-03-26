use super::*;
use crate::types::{Instruction, IrProgram, Visibility};

fn empty_inputs() -> HashMap<String, FieldElement> {
    HashMap::new()
}

fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}

#[test]
fn eval_const() {
    let mut p = IrProgram::new();
    let v = p.fresh_var();
    p.push(Instruction::Const {
        result: v,
        value: fe(42),
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&v], fe(42));
}

#[test]
fn eval_input() {
    let mut p = IrProgram::new();
    let v = p.fresh_var();
    p.push(Instruction::Input {
        result: v,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), fe(7));
    let vals = evaluate(&p, &inputs).unwrap();
    assert_eq!(vals[&v], fe(7));
}

#[test]
fn eval_missing_input_error() {
    let mut p = IrProgram::new();
    let v = p.fresh_var();
    p.push(Instruction::Input {
        result: v,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::MissingInput(ref n) if n == "x"));
}

#[test]
fn eval_add() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(3),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(4),
    });
    p.push(Instruction::Add {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], fe(7));
}

#[test]
fn eval_sub() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(10),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(3),
    });
    p.push(Instruction::Sub {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], fe(7));
}

#[test]
fn eval_mul() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(6),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(7),
    });
    p.push(Instruction::Mul {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], fe(42));
}

#[test]
fn eval_div() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(42),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(6),
    });
    p.push(Instruction::Div {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], fe(7));
}

#[test]
fn eval_neg() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(5),
    });
    p.push(Instruction::Neg {
        result: b,
        operand: a,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&b], fe(5).neg());
}

#[test]
fn eval_div_by_zero_error() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(1),
    });
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::Div {
        result: c,
        lhs: a,
        rhs: b,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::DivisionByZero { .. }));
}

#[test]
fn eval_mux_true() {
    let mut p = IrProgram::new();
    let c = p.fresh_var();
    let t = p.fresh_var();
    let f = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: c,
        value: FieldElement::ONE,
    });
    p.push(Instruction::Const {
        result: t,
        value: fe(10),
    });
    p.push(Instruction::Const {
        result: f,
        value: fe(20),
    });
    p.push(Instruction::Mux {
        result: r,
        cond: c,
        if_true: t,
        if_false: f,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&r], fe(10));
}

#[test]
fn eval_mux_false() {
    let mut p = IrProgram::new();
    let c = p.fresh_var();
    let t = p.fresh_var();
    let f = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: c,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::Const {
        result: t,
        value: fe(10),
    });
    p.push(Instruction::Const {
        result: f,
        value: fe(20),
    });
    p.push(Instruction::Mux {
        result: r,
        cond: c,
        if_true: t,
        if_false: f,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&r], fe(20));
}

#[test]
fn eval_mux_non_boolean_error() {
    let mut p = IrProgram::new();
    let c = p.fresh_var();
    let t = p.fresh_var();
    let f = p.fresh_var();
    let r = p.fresh_var();
    p.push(Instruction::Const {
        result: c,
        value: fe(2),
    });
    p.push(Instruction::Const {
        result: t,
        value: fe(10),
    });
    p.push(Instruction::Const {
        result: f,
        value: fe(20),
    });
    p.push(Instruction::Mux {
        result: r,
        cond: c,
        if_true: t,
        if_false: f,
    });
    let err = evaluate(&p, &empty_inputs()).unwrap_err();
    assert!(matches!(*err, EvalError::NonBooleanMuxCondition { .. }));
}

#[test]
fn eval_poseidon_matches_native() {
    let params = PoseidonParams::bn254_t3();
    let l = fe(1);
    let r = fe(2);
    let expected = poseidon_hash(&params, l, r);

    let mut p = IrProgram::new();
    let lv = p.fresh_var();
    let rv = p.fresh_var();
    let hv = p.fresh_var();
    p.push(Instruction::Const {
        result: lv,
        value: l,
    });
    p.push(Instruction::Const {
        result: rv,
        value: r,
    });
    p.push(Instruction::PoseidonHash {
        result: hv,
        left: lv,
        right: rv,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&hv], expected);
}

#[test]
fn eval_not() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    p.push(Instruction::Not {
        result: b,
        operand: a,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&b], FieldElement::ZERO);
}

#[test]
fn eval_and() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::And {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ZERO);
}

#[test]
fn eval_or() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::ONE,
    });
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::ZERO,
    });
    p.push(Instruction::Or {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ONE);
}

#[test]
fn eval_is_eq() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(5),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(5),
    });
    p.push(Instruction::IsEq {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ONE);
}

#[test]
fn eval_is_neq() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(3),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(5),
    });
    p.push(Instruction::IsNeq {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ONE);
}

#[test]
fn eval_is_lt() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(3),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(5),
    });
    p.push(Instruction::IsLt {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ONE);

    // Not less
    let mut p2 = IrProgram::new();
    let a2 = p2.fresh_var();
    let b2 = p2.fresh_var();
    let c2 = p2.fresh_var();
    p2.push(Instruction::Const {
        result: a2,
        value: fe(5),
    });
    p2.push(Instruction::Const {
        result: b2,
        value: fe(3),
    });
    p2.push(Instruction::IsLt {
        result: c2,
        lhs: a2,
        rhs: b2,
    });
    let vals2 = evaluate(&p2, &empty_inputs()).unwrap();
    assert_eq!(vals2[&c2], FieldElement::ZERO);
}

#[test]
fn eval_is_le() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    let b = p.fresh_var();
    let c = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: fe(5),
    });
    p.push(Instruction::Const {
        result: b,
        value: fe(5),
    });
    p.push(Instruction::IsLe {
        result: c,
        lhs: a,
        rhs: b,
    });
    let vals = evaluate(&p, &empty_inputs()).unwrap();
    assert_eq!(vals[&c], FieldElement::ONE);
}

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

#[test]
fn fits_in_bits_edge_cases() {
    assert!(fits_in_bits(&fe(0), 1));
    assert!(fits_in_bits(&fe(1), 1));
    assert!(!fits_in_bits(&fe(2), 1));
    assert!(fits_in_bits(&fe(255), 8));
    assert!(!fits_in_bits(&fe(256), 8));
    assert!(fits_in_bits(&fe(u64::MAX), 64));
    assert!(!fits_in_bits(&fe(u64::MAX), 63));
}

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
