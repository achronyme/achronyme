use std::collections::HashMap;

use ir_forge::types::{CircuitExpr, FieldConst};
use memory::{Bn254Fr, FieldElement};

use super::eval::eval_hint;
use super::limbs::{bit_mask_limbs, shift_right_limbs};

type Fe = FieldElement<Bn254Fr>;

fn fe(v: u64) -> Fe {
    Fe::from_u64(v)
}

fn make_env(pairs: &[(&str, u64)]) -> HashMap<String, Fe> {
    pairs.iter().map(|(k, v)| (k.to_string(), fe(*v))).collect()
}

#[test]
fn eval_const() {
    let env: HashMap<String, Fe> = HashMap::new();
    let expr = CircuitExpr::Const(FieldConst::from_u64(42));
    assert_eq!(eval_hint(&expr, &env), Some(fe(42)));
}

#[test]
fn eval_input() {
    let env = make_env(&[("x", 10)]);
    let expr = CircuitExpr::Input("x".to_string());
    assert_eq!(eval_hint(&expr, &env), Some(fe(10)));
}

#[test]
fn eval_shift_right() {
    let env = make_env(&[("x", 13)]);
    // x >> 1 = 6 (13 = 1101, >> 1 = 110 = 6)
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Input("x".to_string())),
        shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
        num_bits: 254,
    };
    assert_eq!(eval_hint(&expr, &env), Some(fe(6)));
}

#[test]
fn eval_bit_and() {
    let env = make_env(&[("x", 13)]);
    // 13 & 1 = 1
    let expr = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::Input("x".to_string())),
        rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
        num_bits: 254,
    };
    assert_eq!(eval_hint(&expr, &env), Some(fe(1)));
}

#[test]
fn eval_shift_and_mask() {
    let env = make_env(&[("in", 13)]);
    // (in >> 3) & 1 = bit 3 of 13 (1101) = 1
    let expr = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Input("in".to_string())),
            shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(3))),
            num_bits: 254,
        }),
        rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
        num_bits: 254,
    };
    assert_eq!(eval_hint(&expr, &env), Some(fe(1)));

    // (in >> 1) & 1 = bit 1 of 13 (1101) = 0
    let expr2 = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Input("in".to_string())),
            shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
            num_bits: 254,
        }),
        rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
        num_bits: 254,
    };
    assert_eq!(eval_hint(&expr2, &env), Some(fe(0)));
}

#[test]
fn eval_arithmetic() {
    let env = make_env(&[("a", 3), ("b", 7)]);
    let expr = CircuitExpr::BinOp {
        op: ir_forge::types::CircuitBinOp::Mul,
        lhs: Box::new(CircuitExpr::Input("a".to_string())),
        rhs: Box::new(CircuitExpr::Input("b".to_string())),
    };
    assert_eq!(eval_hint(&expr, &env), Some(fe(21)));
}

#[test]
fn shift_right_limbs_basic() {
    assert_eq!(shift_right_limbs([13, 0, 0, 0], 1), [6, 0, 0, 0]);
    assert_eq!(shift_right_limbs([13, 0, 0, 0], 3), [1, 0, 0, 0]);
    assert_eq!(shift_right_limbs([0, 1, 0, 0], 64), [1, 0, 0, 0]);
}

#[test]
fn bit_mask_limbs_basic() {
    assert_eq!(bit_mask_limbs(8), [0xFF, 0, 0, 0]);
    assert_eq!(bit_mask_limbs(64), [u64::MAX, 0, 0, 0]);
    assert_eq!(bit_mask_limbs(1), [1, 0, 0, 0]);
}
