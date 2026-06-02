use super::*;

// ── Arithmetic ──────────────────────────────────────────────────

#[test]
fn lower_addition() {
    let expr = parse_expr("a + b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            ..
        }
    ));
}

#[test]
fn lower_subtraction() {
    let expr = parse_expr("a - b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            ..
        }
    ));
}

#[test]
fn lower_multiplication() {
    let expr = parse_expr("a * b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            ..
        }
    ));
}

#[test]
fn lower_division() {
    let expr = parse_expr("a / b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            ..
        }
    ));
}

#[test]
fn lower_int_div() {
    let expr = parse_expr(r"a \ b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::IntDiv { .. }
    ));
}

#[test]
fn lower_modulo() {
    let expr = parse_expr("a % b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::IntMod { .. }
    ));
}

#[test]
fn lower_power() {
    let expr = parse_expr("a ** 3");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::Pow { exp, .. } => assert_eq!(exp, 3),
        other => panic!("expected Pow, got {:?}", other),
    }
}

#[test]
fn lower_power_non_const_is_error() {
    let expr = parse_expr("a ** b");
    assert!(lower_expr(&expr, &make_env(), &mut make_ctx()).is_err());
}

// ── Comparisons ─────────────────────────────────────────────────

#[test]
fn lower_equality() {
    let expr = parse_expr("a == b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Comparison {
            op: CircuitCmpOp::Eq,
            ..
        }
    ));
}

#[test]
fn lower_neq() {
    let expr = parse_expr("a != b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Comparison {
            op: CircuitCmpOp::Neq,
            ..
        }
    ));
}

#[test]
fn lower_less_than() {
    let expr = parse_expr("a < b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Comparison {
            op: CircuitCmpOp::Lt,
            ..
        }
    ));
}

// ── Boolean ─────────────────────────────────────────────────────

#[test]
fn lower_and() {
    let expr = parse_expr("a && b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BoolOp {
            op: CircuitBoolOp::And,
            ..
        }
    ));
}

#[test]
fn lower_or() {
    let expr = parse_expr("a || b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BoolOp {
            op: CircuitBoolOp::Or,
            ..
        }
    ));
}

// ── Unary ───────────────────────────────────────────────────────

#[test]
fn lower_negation() {
    let expr = parse_expr("-a");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Neg,
            ..
        }
    ));
}

#[test]
fn lower_not() {
    let expr = parse_expr("!a");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Not,
            ..
        }
    ));
}

#[test]
fn lower_bitnot_via_unary() {
    let expr = parse_expr("~a");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BitNot { num_bits: 254, .. }
    ));
}

// ── Ternary → Mux ───────────────────────────────────────────────

#[test]
fn lower_ternary_to_mux() {
    let expr = parse_expr("a == 0 ? 1 : 0");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Mux { .. }
    ));
}

// ── Array index ─────────────────────────────────────────────────

#[test]
fn lower_array_index() {
    let expr = parse_expr("bits[0]");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::ArrayIndex { array, .. } => assert_eq!(array, "bits"),
        other => panic!("expected ArrayIndex, got {:?}", other),
    }
}

// ── Nested expression ───────────────────────────────────────────

#[test]
fn lower_nested_arithmetic() {
    let expr = parse_expr("(a + b) * (a - b)");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            ..
        }
    ));
}

#[test]
fn lower_complex_iszero_pattern() {
    let expr = parse_expr("a != 0 ? 1 : 0");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Mux { .. }
    ));
}

// ── Bitwise operations ────────────────────────────────────────

#[test]
fn lower_bitwise_and() {
    let expr = parse_expr("a & b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BitAnd { num_bits: 254, .. }
    ));
}

#[test]
fn lower_bitwise_or() {
    let expr = parse_expr("a | b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BitOr { num_bits: 254, .. }
    ));
}

#[test]
fn lower_bitwise_xor() {
    let expr = parse_expr("a ^ b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BitXor { num_bits: 254, .. }
    ));
}

#[test]
fn lower_bitwise_not() {
    let expr = parse_expr("~a");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::BitNot { num_bits: 254, .. }
    ));
}

#[test]
fn lower_shift_right() {
    let expr = parse_expr("a >> 3");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::ShiftR {
            shift, num_bits, ..
        } => {
            assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(3)));
            assert_eq!(num_bits, 254);
        }
        other => panic!("expected ShiftR, got {:?}", other),
    }
}

#[test]
fn lower_shift_left() {
    let expr = parse_expr("a << 1");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::ShiftL {
            shift, num_bits, ..
        } => {
            assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(1)));
            assert_eq!(num_bits, 254);
        }
        other => panic!("expected ShiftL, got {:?}", other),
    }
}

#[test]
fn lower_shift_variable_amount() {
    let expr = parse_expr("a >> b");
    assert!(matches!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::ShiftR { .. }
    ));
}

#[test]
fn lower_shift_non_const_is_now_ok() {
    let expr = parse_expr("a >> b");
    assert!(lower_expr(&expr, &make_env(), &mut make_ctx()).is_ok());
}
