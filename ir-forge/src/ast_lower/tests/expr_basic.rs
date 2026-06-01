use super::*;

// --- Literals ---

#[test]
fn number_literal() {
    let expr = compile_single_expr("42").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(42)));
}

#[test]
fn negative_number() {
    let expr = compile_single_expr("-7").unwrap();
    assert_eq!(
        expr,
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Neg,
            operand: Box::new(CircuitExpr::Const(FieldConst::from_u64(7))),
        }
    );
}

#[test]
fn field_literal_decimal() {
    let expr = compile_single_expr("0p42").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(42)));
}

#[test]
fn field_literal_hex() {
    let expr = compile_single_expr("0pxFF").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(255)));
}

#[test]
fn bool_true() {
    let expr = compile_single_expr("true").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::one()));
}

#[test]
fn bool_false() {
    let expr = compile_single_expr("false").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::zero()));
}

#[test]
fn negative_field_literal() {
    // Negative numbers go through UnaryOp(Neg, Number)
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("-0p42", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Neg,
            ..
        }
    ));
}

// --- Identifiers ---

#[test]
fn ident_scalar() {
    let expr = compile_expr_with_scope("x", &[("x", CompEnvValue::Scalar("x".into()))]).unwrap();
    assert_eq!(expr, CircuitExpr::Var("x".into()));
}

#[test]
fn ident_capture() {
    let expr = compile_expr_with_scope("n", &[("n", CompEnvValue::Capture("n".into()))]).unwrap();
    assert_eq!(expr, CircuitExpr::Capture("n".into()));
}

#[test]
fn ident_array_as_scalar_errors() {
    let err = compile_expr_with_scope("arr", &[("arr", CompEnvValue::Array(vec!["arr_0".into()]))])
        .unwrap_err();
    assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
}

#[test]
fn ident_undeclared_errors() {
    let err = compile_single_expr("unknown").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::UndeclaredVariable { name, .. } if name == "unknown"
    ));
}

// --- Binary operations ---

#[test]
fn binop_add() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a + b", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Var("a".into())),
            rhs: Box::new(CircuitExpr::Var("b".into())),
        }
    );
}

#[test]
fn binop_mul() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x * 2", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            ..
        }
    ));
}

#[test]
fn binop_mod_rejected() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let err = compile_expr_with_scope("a % b", &scope).unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

// --- Comparisons ---

#[test]
fn comparison_eq() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a == b", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::Comparison {
            op: CircuitCmpOp::Eq,
            ..
        }
    ));
}

#[test]
fn comparison_gt() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x > 5", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::Comparison {
            op: CircuitCmpOp::Gt,
            ..
        }
    ));
}

// --- Boolean ops ---

#[test]
fn bool_and() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a && b", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::BoolOp {
            op: CircuitBoolOp::And,
            ..
        }
    ));
}

#[test]
fn bool_or() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a || b", &scope).unwrap();
    assert!(matches!(
        expr,
        CircuitExpr::BoolOp {
            op: CircuitBoolOp::Or,
            ..
        }
    ));
}

// --- Unary ops ---

#[test]
fn unary_neg() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("-x", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Neg,
            operand: Box::new(CircuitExpr::Var("x".into())),
        }
    );
}

#[test]
fn unary_not() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("!x", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Not,
            operand: Box::new(CircuitExpr::Var("x".into())),
        }
    );
}

#[test]
fn double_negation_cancelled() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("--x", &scope).unwrap();
    // Double negation cancels to just x
    assert_eq!(expr, CircuitExpr::Var("x".into()));
}

// --- Power ---

#[test]
fn pow_constant_exponent() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x ^ 3", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::Pow {
            base: Box::new(CircuitExpr::Var("x".into())),
            exp: 3,
        }
    );
}

#[test]
fn pow_variable_exponent_rejected() {
    let scope = [
        ("x", CompEnvValue::Scalar("x".into())),
        ("n", CompEnvValue::Scalar("n".into())),
    ];
    let err = compile_expr_with_scope("x ^ n", &scope).unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

// --- Rejections ---

#[test]
fn string_rejected() {
    let err = compile_single_expr("\"hello\"").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "string"
    ));
}

#[test]
fn nil_rejected() {
    let err = compile_single_expr("nil").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "nil"
    ));
}

#[test]
fn closure_rejected() {
    let err = compile_single_expr("fn(x) { x }").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

// --- Static access ---
