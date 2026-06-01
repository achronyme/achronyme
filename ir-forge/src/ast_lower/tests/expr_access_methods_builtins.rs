use super::*;

#[test]
fn static_field_zero() {
    let expr = compile_single_expr("Field::ZERO").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::zero()));
}

#[test]
fn static_field_one() {
    let expr = compile_single_expr("Field::ONE").unwrap();
    assert_eq!(expr, CircuitExpr::Const(FieldConst::one()));
}

#[test]
fn static_int_max() {
    let expr = compile_single_expr("Int::MAX").unwrap();
    assert_eq!(
        expr,
        CircuitExpr::Const(FieldConst::from_field(FieldElement::<Bn254Fr>::from_i64(
            memory::I60_MAX
        )))
    );
}

#[test]
fn static_int_min() {
    let expr = compile_single_expr("Int::MIN").unwrap();
    assert_eq!(
        expr,
        CircuitExpr::Const(FieldConst::from_field(FieldElement::<Bn254Fr>::from_i64(
            memory::I60_MIN
        )))
    );
}

#[test]
fn static_field_order_rejected() {
    let err = compile_single_expr("Field::ORDER").unwrap_err();
    assert!(
        matches!(err, ProveIrError::StaticAccessNotConstrainable { ref type_name, ref member, .. }
            if type_name == "Field" && member == "ORDER"
        ),
        "expected StaticAccessNotConstrainable, got {err}"
    );
}

#[test]
fn static_bigint_rejected() {
    let err = compile_single_expr("BigInt::from_bits").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "BigInt"
    ));
}

#[test]
fn static_unknown_rejected() {
    let err = compile_single_expr("Foo::BAR").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn static_in_expression() {
    // Field::ONE + Field::ZERO should work in arithmetic
    let expr = compile_single_expr("Field::ONE + Field::ZERO").unwrap();
    assert_eq!(
        expr,
        CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(FieldConst::one())),
            rhs: Box::new(CircuitExpr::Const(FieldConst::zero())),
        }
    );
}

// --- Method desugaring ---

#[test]
fn method_to_field_is_identity() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x.to_field()", &scope).unwrap();
    assert_eq!(expr, CircuitExpr::Var("x".into()));
}

#[test]
fn method_abs_desugars_to_mux() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x.abs()", &scope).unwrap();
    assert!(
        matches!(expr, CircuitExpr::Mux { .. }),
        "abs should desugar to Mux, got {expr:?}"
    );
}

#[test]
fn method_min_desugars_to_mux() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a.min(b)", &scope).unwrap();
    // min(a, b) = mux(a < b, a, b)
    if let CircuitExpr::Mux {
        if_true, if_false, ..
    } = &expr
    {
        assert_eq!(**if_true, CircuitExpr::Var("a".into()));
        assert_eq!(**if_false, CircuitExpr::Var("b".into()));
    } else {
        panic!("expected Mux, got {expr:?}");
    }
}

#[test]
fn method_max_desugars_to_mux() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("a.max(b)", &scope).unwrap();
    // max(a, b) = mux(a < b, b, a)
    if let CircuitExpr::Mux {
        if_true, if_false, ..
    } = &expr
    {
        assert_eq!(**if_true, CircuitExpr::Var("b".into()));
        assert_eq!(**if_false, CircuitExpr::Var("a".into()));
    } else {
        panic!("expected Mux, got {expr:?}");
    }
}

#[test]
fn method_pow_desugars() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("x.pow(3)", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::Pow {
            base: Box::new(CircuitExpr::Var("x".into())),
            exp: 3,
        }
    );
}

#[test]
fn method_len_on_array() {
    let scope = [(
        "arr",
        CompEnvValue::Array(vec!["arr_0".into(), "arr_1".into()]),
    )];
    let expr = compile_expr_with_scope("arr.len()", &scope).unwrap();
    assert_eq!(expr, CircuitExpr::ArrayLen("arr".into()));
}

#[test]
fn method_to_string_rejected() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let err = compile_expr_with_scope("x.to_string()", &scope).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::MethodNotConstrainable { ref method, .. } if method == "to_string"
    ));
}

#[test]
fn method_push_rejected() {
    let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
    let err = compile_expr_with_scope("arr.push(1)", &scope).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::MethodNotConstrainable { ref method, .. } if method == "push"
    ));
}

#[test]
fn method_filter_rejected() {
    let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
    let err = compile_expr_with_scope("arr.filter(fn(x) { x })", &scope).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::MethodNotConstrainable { ref method, .. } if method == "filter"
    ));
}

#[test]
fn method_keys_rejected() {
    let scope = [("m", CompEnvValue::Scalar("m".into()))];
    let err = compile_expr_with_scope("m.keys()", &scope).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::MethodNotConstrainable { ref method, .. } if method == "keys"
    ));
}

#[test]
fn method_unknown_rejected() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let err = compile_expr_with_scope("x.foobar()", &scope).unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

// --- Builtin calls ---

#[test]
fn builtin_poseidon() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("poseidon(a, b)", &scope).unwrap();
    assert!(matches!(expr, CircuitExpr::PoseidonHash { .. }));
}

#[test]
fn builtin_poseidon_many() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
        ("c", CompEnvValue::Scalar("c".into())),
    ];
    let expr = compile_expr_with_scope("poseidon_many(a, b, c)", &scope).unwrap();
    if let CircuitExpr::PoseidonMany(args) = &expr {
        assert_eq!(args.len(), 3);
    } else {
        panic!("expected PoseidonMany, got {expr:?}");
    }
}

#[test]
fn builtin_mux() {
    let scope = [
        ("c", CompEnvValue::Scalar("c".into())),
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("mux(c, a, b)", &scope).unwrap();
    assert!(matches!(expr, CircuitExpr::Mux { .. }));
}

#[test]
fn builtin_range_check() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("range_check(x, 8)", &scope).unwrap();
    assert_eq!(
        expr,
        CircuitExpr::RangeCheck {
            value: Box::new(CircuitExpr::Var("x".into())),
            bits: 8,
        }
    );
}

#[test]
fn builtin_poseidon_wrong_arity() {
    let scope = [("a", CompEnvValue::Scalar("a".into()))];
    let err = compile_expr_with_scope("poseidon(a)", &scope).unwrap_err();
    assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
}

// --- Nested expressions ---

#[test]
fn nested_arithmetic() {
    let scope = [
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
        ("c", CompEnvValue::Scalar("c".into())),
    ];
    let expr = compile_expr_with_scope("a * b + c", &scope).unwrap();
    // Should be Add(Mul(a, b), c)
    assert!(matches!(
        expr,
        CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            ..
        }
    ));
}
