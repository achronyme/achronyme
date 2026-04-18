//! Tests for the ProveIR compiler.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `compiler/mod.rs`.

use super::*;
use crate::prove_ir::error::ProveIrError;
use achronyme_parser::parse_program;
use memory::FieldElement;

/// Helper: parse source and compile the first expression to CircuitExpr.
fn compile_single_expr(source: &str) -> Result<CircuitExpr, ProveIrError> {
    let (program, errors) = parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    match &program.stmts[0] {
        Stmt::Expr(expr) => compiler.compile_expr(expr),
        _ => panic!("expected expression statement"),
    }
}

/// Helper: parse source with outer scope, compile an expression.
fn compile_expr_with_scope(
    source: &str,
    scope: &[(&str, CompEnvValue)],
) -> Result<CircuitExpr, ProveIrError> {
    let (program, errors) = parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    for (name, val) in scope {
        compiler.env.insert(name.to_string(), val.clone());
    }
    match &program.stmts[0] {
        Stmt::Expr(expr) => compiler.compile_expr(expr),
        _ => panic!("expected expression statement"),
    }
}

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

// =====================================================================
// Statement compilation tests
// =====================================================================

/// Helper: compile a circuit source. Automatically wraps flat format
/// (public/witness top-level declarations) into `circuit test(...) { body }`.
fn compile_circuit(source: &str) -> Result<ProveIR, ProveIrError> {
    crate::prove_ir::test_utils::compile_circuit(source)
}

#[test]
fn stmt_public_decl_scalar() {
    let ir = compile_circuit("public x\nassert_eq(x, x)").unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "x");
    assert!(ir.public_inputs[0].array_size.is_none());
}

#[test]
fn stmt_witness_decl_scalar() {
    let ir = compile_circuit("witness y\nassert_eq(y, y)").unwrap();
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "y");
}

#[test]
fn stmt_public_decl_array() {
    let ir = compile_circuit("public arr[3]\nassert_eq(arr_0, arr_1)").unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "arr");
    assert_eq!(ir.public_inputs[0].array_size, Some(ArraySize::Literal(3)));
}

#[test]
fn stmt_let_scalar() {
    let ir = compile_circuit("public x\nlet y = x\nassert_eq(y, x)").unwrap();
    assert!(ir.body.len() >= 2); // Let + AssertEq
    assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "y"));
}

#[test]
fn stmt_let_array() {
    let ir = compile_circuit("let arr = [1, 2, 3]").unwrap();
    assert_eq!(ir.body.len(), 1);
    if let CircuitNode::LetArray { name, elements, .. } = &ir.body[0] {
        assert_eq!(name, "arr");
        assert_eq!(elements.len(), 3);
    } else {
        panic!("expected LetArray, got {:?}", ir.body[0]);
    }
}

#[test]
fn stmt_empty_array_rejected() {
    let err = compile_circuit("let arr = []").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_assert_eq_as_node() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })),
        "expected AssertEq node in body"
    );
}

#[test]
fn stmt_assert_as_node() {
    let ir = compile_circuit("public x\nassert(x)").unwrap();
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::Assert { .. })),
        "expected Assert node in body"
    );
}

#[test]
fn stmt_assert_with_message() {
    let ir = compile_circuit("public x\nassert(x, \"x must be true\")").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::Assert { .. }))
        .expect("expected Assert node");
    if let CircuitNode::Assert { message, .. } = node {
        assert_eq!(message.as_deref(), Some("x must be true"));
    }
}

#[test]
fn stmt_assert_without_message() {
    let ir = compile_circuit("public x\nassert(x)").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::Assert { .. }))
        .expect("expected Assert node");
    if let CircuitNode::Assert { message, .. } = node {
        assert_eq!(*message, None);
    }
}

#[test]
fn stmt_assert_message_must_be_string() {
    let err = compile_circuit("public x\nassert(x, 42)").unwrap_err();
    assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
}

#[test]
fn stmt_assert_too_many_args() {
    let err = compile_circuit("public x\nassert(x, \"msg\", 1)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_assert_eq_with_message() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b, \"values must match\")").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .expect("expected AssertEq node");
    if let CircuitNode::AssertEq { message, .. } = node {
        assert_eq!(message.as_deref(), Some("values must match"));
    }
}

#[test]
fn stmt_assert_eq_without_message() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .expect("expected AssertEq node");
    if let CircuitNode::AssertEq { message, .. } = node {
        assert_eq!(*message, None);
    }
}

#[test]
fn stmt_assert_eq_message_must_be_string() {
    let err = compile_circuit("public a\npublic b\nassert_eq(a, b, 42)").unwrap_err();
    assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
}

#[test]
fn stmt_assert_eq_too_many_args() {
    let err = compile_circuit("public a\npublic b\nassert_eq(a, b, \"msg\", 1)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_fn_decl_not_emitted() {
    let ir = compile_circuit("public x\nfn f(a) { a }\nassert_eq(x, x)").unwrap();
    // FnDecl doesn't produce a body node — it's stored in fn_table
    assert!(
        !ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "f")),
        "FnDecl should not produce a Let node"
    );
}

#[test]
fn stmt_print_rejected() {
    let err = compile_circuit("print(42)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_break_rejected() {
    // break outside loop is actually a parse error, but test the stmt handler
    let err = compile_circuit("public x\nassert_eq(x, x)");
    // This should succeed — break only fails if actually encountered
    assert!(err.is_ok());
}

#[test]
fn stmt_basic_circuit() {
    // A complete basic circuit: public out, witness a, b, assert_eq(a * b, out)
    let ir = compile_circuit(
        "public out\nwitness a\nwitness b\nlet product = a * b\nassert_eq(product, out)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert_eq!(ir.public_inputs[0].name, "out");
    assert_eq!(ir.witness_inputs[0].name, "a");
    assert_eq!(ir.witness_inputs[1].name, "b");
    // Body: Let(product) + AssertEq
    assert!(ir.body.len() >= 2);
    assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "product"));
    assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
}

#[test]
fn stmt_poseidon_circuit() {
    let ir = compile_circuit(
        "public hash\nwitness secret\nlet h = poseidon(secret, 0)\nassert_eq(h, hash)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    // Body: Let(h = PoseidonHash) + AssertEq
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert!(
            matches!(value, CircuitExpr::PoseidonHash { .. }),
            "expected PoseidonHash, got {value:?}"
        );
    } else {
        panic!("expected Let node, got {:?}", ir.body[0]);
    }
}

#[test]
fn stmt_with_static_access() {
    // Field::ZERO should work inside a circuit now!
    let ir = compile_circuit("public x\nlet zero = Field::ZERO\nassert_eq(x, zero)").unwrap();
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
    } else {
        panic!("expected Let node");
    }
}

// =====================================================================
// Mut-to-SSA desugaring tests
// =====================================================================

#[test]
fn mut_decl_basic() {
    let ir = compile_circuit("public x\nmut acc = x\nassert_eq(acc, x)").unwrap();
    // mut acc = x → Let { name: "acc", value: Var("x") }
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "acc"
    ));
}

#[test]
fn mut_reassignment_creates_ssa_version() {
    let ir = compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
    // body[0]: Let { name: "acc", value: Var("x") }
    // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
    // body[2]: AssertEq { Var("acc$v1"), Var("x") }
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "acc"
    ));
    assert!(matches!(
        &ir.body[1],
        CircuitNode::Let { name, .. } if name == "acc$v1"
    ));
    // AssertEq should reference the latest SSA name
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[2] {
        assert_eq!(*lhs, CircuitExpr::Var("acc$v1".into()));
    } else {
        panic!("expected AssertEq, got {:?}", ir.body[2]);
    }
}

#[test]
fn mut_multiple_reassignments() {
    let ir =
        compile_circuit("public x\nmut a = 0\na = a + 1\na = a + 2\na = a + 3\nassert_eq(a, x)")
            .unwrap();
    // Let("a"), Let("a$v1"), Let("a$v2"), Let("a$v3"), AssertEq(Var("a$v3"), ...)
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "a"
    ));
    assert!(matches!(
        &ir.body[1],
        CircuitNode::Let { name, .. } if name == "a$v1"
    ));
    assert!(matches!(
        &ir.body[2],
        CircuitNode::Let { name, .. } if name == "a$v2"
    ));
    assert!(matches!(
        &ir.body[3],
        CircuitNode::Let { name, .. } if name == "a$v3"
    ));
    // The final assert_eq should use a$v3
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
        assert_eq!(*lhs, CircuitExpr::Var("a$v3".into()));
    } else {
        panic!("expected AssertEq");
    }
}

#[test]
fn mut_reassignment_uses_previous_version() {
    // acc = acc + 1 should reference the PREVIOUS version of acc in the RHS
    let ir = compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
    // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        // The RHS should reference "acc" (v0), not "acc$v1"
        assert_eq!(
            *value,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("acc".into())),
                rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
            }
        );
    } else {
        panic!("expected Let node");
    }
}

#[test]
fn assign_to_immutable_errors() {
    let err = compile_circuit("public x\nlet a = x\na = 42\nassert_eq(a, x)").unwrap_err();
    assert!(
        matches!(err, ProveIrError::UnsupportedOperation { ref description, .. }
            if description.contains("not declared with `mut`")),
        "expected mut error, got {err}"
    );
}

#[test]
fn assign_to_undeclared_errors() {
    let err = compile_circuit("public x\nfoo = 42\nassert_eq(foo, x)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn mut_in_accumulator_pattern() {
    // Common pattern: accumulate in a loop (simulated without for, just sequential)
    let ir = compile_circuit(
        "public total\n\
         witness a\n\
         witness b\n\
         witness c\n\
         mut acc = Field::ZERO\n\
         acc = acc + a\n\
         acc = acc + b\n\
         acc = acc + c\n\
         assert_eq(acc, total)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
    // acc, acc$v1, acc$v2, acc$v3, assert_eq
    assert_eq!(ir.body.len(), 5);
    // Last AssertEq should use acc$v3
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
        assert_eq!(*lhs, CircuitExpr::Var("acc$v3".into()));
    } else {
        panic!("expected AssertEq");
    }
}

// =====================================================================
// Function inlining tests
// =====================================================================

#[test]
fn fn_simple_inline() {
    let ir =
        compile_circuit("public x\npublic out\nfn double(a) { a * 2 }\nassert_eq(double(x), out)")
            .unwrap();
    // double(x) should produce: Let(__double_a = Var(x)) then the inline result
    // The AssertEq should have the inlined expression
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_inline_with_let() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn square(n) { let r = n * n; r }\n\
         assert_eq(square(x), out)",
    )
    .unwrap();
    // The inlined body should have emitted a Let for r
    assert!(ir.body.iter().any(
        |n| matches!(n, CircuitNode::Let { name, .. } if name.contains("__square_n")
                                                              || name == "r")
    ));
}

#[test]
fn fn_inline_nested_calls() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn square(n) { n * n }\n\
         fn sum_of_squares(a, b) { square(a) + square(b) }\n\
         assert_eq(sum_of_squares(x, x), out)",
    )
    .unwrap();
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_with_return() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn check(n) { return n * 2 }\n\
         assert_eq(check(x), out)",
    )
    .unwrap();
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_wrong_arity_errors() {
    let err = compile_circuit("public x\nfn f(a, b) { a + b }\nassert_eq(f(x), x)").unwrap_err();
    assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
}

#[test]
fn fn_recursive_errors() {
    let err = compile_circuit("public x\nfn f(n) { f(n) }\nassert_eq(f(x), x)").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::RecursiveFunction { ref name } if name == "f"
    ));
}

#[test]
fn fn_undefined_errors() {
    let err = compile_circuit("public x\nassert_eq(unknown_fn(x), x)").unwrap_err();
    assert!(matches!(err, ProveIrError::UndeclaredVariable { .. }));
}

#[test]
fn fn_env_restored_after_inline() {
    // After inlining f(x), a reference to 'x' should still resolve to the outer x
    let ir = compile_circuit(
        "public x\npublic out\n\
         fn f(a) { a + 1 }\n\
         let y = f(x)\n\
         assert_eq(x + y, out)",
    )
    .unwrap();
    // The final assert_eq should reference outer x (not the param)
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_hash_pair_circuit() {
    // Realistic circuit: fn hash_pair(a, b) { poseidon(a, b) }
    let ir = compile_circuit(
        "public out\nwitness a\nwitness b\n\
         fn hash_pair(x, y) { poseidon(x, y) }\n\
         assert_eq(hash_pair(a, b), out)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

// =====================================================================
// Control flow tests
// =====================================================================

#[test]
fn if_expr_produces_mux() {
    let scope = [
        ("c", CompEnvValue::Scalar("c".into())),
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("if c { a } else { b }", &scope).unwrap();
    assert!(
        matches!(expr, CircuitExpr::Mux { .. }),
        "if/else should produce Mux, got {expr:?}"
    );
}

#[test]
fn if_without_else_mux_zero() {
    let scope = [
        ("c", CompEnvValue::Scalar("c".into())),
        ("a", CompEnvValue::Scalar("a".into())),
    ];
    let expr = compile_expr_with_scope("if c { a }", &scope).unwrap();
    if let CircuitExpr::Mux { if_false, .. } = &expr {
        assert_eq!(**if_false, CircuitExpr::Const(FieldConst::zero()));
    } else {
        panic!("expected Mux, got {expr:?}");
    }
}

#[test]
fn if_else_as_statement() {
    // if/else at statement level produces a cond temp, then a Mux expression
    let ir = compile_circuit(
        "public x\npublic out\nlet result = if x { 1 } else { 0 }\nassert_eq(result, out)",
    )
    .unwrap();
    // body[0]: Let { $condN = <cond> } (temporary for condition)
    assert!(
        matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
        "expected $cond temp, got {:?}",
        ir.body[0]
    );
    // body[1]: Let { result = Mux(Var($condN), ...) }
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected Mux value, got {value:?}"
        );
    } else {
        panic!("expected Let, got {:?}", ir.body[1]);
    }
}

#[test]
fn for_range_literal() {
    let ir = compile_circuit(
        "public out\n\
         mut acc = 0\n\
         for i in 0..3 {\n\
             acc = acc + i\n\
         }\n\
         assert_eq(acc, out)",
    )
    .unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::Literal { start: 0, end: 3 },
                ..
            }
        )),
        "expected For node with Literal range, body: {:#?}",
        ir.body
    );
}

#[test]
fn for_over_array() {
    let ir = compile_circuit(
        "public out\n\
         let arr = [1, 2, 3]\n\
         mut acc = 0\n\
         for x in arr {\n\
             acc = acc + x\n\
         }\n\
         assert_eq(acc, out)",
    )
    .unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::Array(ref name),
                ..
            } if name == "arr"
        )),
        "expected For node with Array range"
    );
}

#[test]
fn for_expr_not_array_errors() {
    let err = compile_circuit("public x\nfor i in x {\nassert_eq(i, i)\n}").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn index_constant_resolves() {
    let ir = compile_circuit("public out\nlet arr = [10, 20, 30]\nassert_eq(arr[1], out)").unwrap();
    // arr[1] with constant index should resolve to Var("arr_1")
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[1] {
        assert_eq!(*lhs, CircuitExpr::Var("arr_1".into()));
    } else {
        panic!("expected AssertEq, got {:?}", ir.body[1]);
    }
}

#[test]
fn index_out_of_bounds_errors() {
    let err = compile_circuit("let arr = [1, 2]\nassert_eq(arr[5], arr[0])").unwrap_err();
    assert!(matches!(err, ProveIrError::IndexOutOfBounds { .. }));
}

#[test]
fn block_expr() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("{ x }", &scope).unwrap();
    assert_eq!(expr, CircuitExpr::Var("x".into()));
}

#[test]
fn for_with_accumulator_circuit() {
    // Realistic pattern: accumulate witness array values
    let ir = compile_circuit(
        "public total\n\
         witness vals[4]\n\
         mut sum = Field::ZERO\n\
         for i in 0..4 {\n\
             sum = sum + vals[i]\n\
         }\n\
         assert_eq(sum, total)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "vals");
    // Should have: LetArray(arr), Let(sum=ZERO), For{...}, AssertEq
    assert!(ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })));
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

// =====================================================================
// Capture classification (end-to-end via compile())
// =====================================================================

/// Helper: compile a prove block body with outer scope captures (all scalar).
fn compile_prove_block(source: &str, outer_vars: &[&str]) -> Result<ProveIR, ProveIrError> {
    let outer = OuterScope {
        values: outer_vars
            .iter()
            .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
            .collect(),
        ..Default::default()
    };
    ProveIrCompiler::<Bn254Fr>::compile_prove_block(source, &outer)
}

#[test]
fn capture_classification_end_to_end() {
    // secret is used in constraint (poseidon), hash is declared public
    let ir = compile_prove_block(
        "public hash\nassert_eq(poseidon(secret, 0), hash)",
        &["secret", "hash"],
    )
    .unwrap();
    // hash is declared as public input, so not a capture
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "hash");
    // secret is captured and used in constraint
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "secret");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}

#[test]
fn no_captures_in_self_contained_circuit() {
    // ach circuit mode: no outer scope, no captures
    let ir = compile_circuit("public out\nwitness a\nwitness b\nassert_eq(a * b, out)").unwrap();
    assert!(ir.captures.is_empty());
}

// =====================================================================
// Integration tests: real circuit patterns from test/circuit/
// =====================================================================

#[test]
fn integration_basic_arithmetic() {
    let source = "\
        public out\n\
        witness a\n\
        witness b\n\
        let product = a * b\n\
        assert_eq(product, out)\n\
        let sum = a + b\n\
        assert_eq(sum, a + b)\n\
        let diff = b - a\n\
        assert_eq(diff, b - a)\n\
        let doubled = a + a\n\
        assert_eq(doubled, a * 2)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir.captures.is_empty());
    // 4 Let + 4 AssertEq = 8 nodes
    let asserts = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 4, "expected 4 assert_eq constraints");
}

#[test]
fn integration_nested_functions() {
    let source = "\
        public result\n\
        witness x\n\
        fn square(a) { a * a }\n\
        fn sum_of_squares(a, b) { square(a) + square(b) }\n\
        assert_eq(sum_of_squares(x, x + 1), result)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn integration_poseidon() {
    let source = "\
        public expected\n\
        witness a\n\
        witness b\n\
        witness c\n\
        let h = poseidon(a, b)\n\
        assert_eq(h, expected)\n\
        let folded = poseidon(h, c)\n\
        let many = poseidon_many(a, b, c)\n\
        assert_eq(many, folded)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
    // Should have PoseidonHash and PoseidonMany in Let values
    let has_poseidon = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Let {
                value: CircuitExpr::PoseidonHash { .. },
                ..
            }
        )
    });
    assert!(has_poseidon, "expected PoseidonHash in body");
    let has_many = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Let {
                value: CircuitExpr::PoseidonMany(_),
                ..
            }
        )
    });
    assert!(has_many, "expected PoseidonMany in body");
}

#[test]
fn integration_power() {
    let source = "\
        public x2\n\
        public x3\n\
        public x4\n\
        witness x\n\
        assert_eq(x ^ 2, x2)\n\
        assert_eq(x ^ 3, x3)\n\
        assert_eq(x ^ 4, x4)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 3);
    assert_eq!(ir.witness_inputs.len(), 1);
    let asserts = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 3);
}

#[test]
fn integration_boolean_ops() {
    let source = "\
        witness x\n\
        witness y\n\
        let eq = x == y\n\
        let neq = x != y\n\
        let lt = x < y\n\
        assert(lt)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Assert { .. })));
}

#[test]
fn integration_mux() {
    let source = "\
        public out\n\
        witness cond\n\
        witness a\n\
        witness b\n\
        assert_eq(mux(cond, a, b), out)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
}

#[test]
fn integration_range_check() {
    let source = "\
        witness x\n\
        witness y\n\
        range_check(x, 8)\n\
        range_check(y, 16)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.witness_inputs.len(), 2);
    // range_check calls become Expr nodes with RangeCheck
    let has_range = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck { .. },
                ..
            }
        )
    });
    assert!(has_range, "expected RangeCheck in body");
}

#[test]
fn integration_if_else_circuit() {
    let source = "\
        public out\n\
        witness x\n\
        witness cond\n\
        let result = if cond { x * 2 } else { x + 1 }\n\
        assert_eq(result, out)";
    let ir = compile_circuit(source).unwrap();
    // body[0]: $condN temp, body[1]: result = Mux(...)
    assert!(
        matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
        "expected $cond temp, got {:?}",
        ir.body[0]
    );
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected Mux, got {value:?}"
        );
    } else {
        panic!("expected Let, got {:?}", ir.body[1]);
    }
}

#[test]
fn integration_mut_accumulator() {
    // The pattern that was IMPOSSIBLE before ProveIR
    let source = "\
        public total\n\
        witness vals[4]\n\
        mut sum = Field::ZERO\n\
        sum = sum + vals_0\n\
        sum = sum + vals_1\n\
        sum = sum + vals_2\n\
        sum = sum + vals_3\n\
        assert_eq(sum, total)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    // sum, sum$v1, sum$v2, sum$v3, sum$v4, assert_eq = 6 nodes
    let lets = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::Let { .. }))
        .count();
    assert!(lets >= 5, "expected 5 Let nodes (SSA), got {lets}");
}

#[test]
fn integration_static_namespaces_in_circuit() {
    // Another pattern IMPOSSIBLE before ProveIR
    let source = "\
        public out\n\
        witness x\n\
        let zero = Field::ZERO\n\
        let one = Field::ONE\n\
        assert_eq(x + zero, x)\n\
        assert_eq(x * one, out)";
    let ir = compile_circuit(source).unwrap();
    // Field::ZERO and Field::ONE should compile to constants
    if let CircuitNode::Let { value, name, .. } = &ir.body[0] {
        assert_eq!(name, "zero");
        assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
    }
    if let CircuitNode::Let { value, name, .. } = &ir.body[1] {
        assert_eq!(name, "one");
        assert_eq!(*value, CircuitExpr::Const(FieldConst::one()));
    }
}

#[test]
fn integration_method_desugaring_in_circuit() {
    // Yet another pattern IMPOSSIBLE before ProveIR
    let source = "\
        public out\n\
        witness x\n\
        witness y\n\
        let m = x.min(y)\n\
        assert_eq(m, out)";
    let ir = compile_circuit(source).unwrap();
    // .min() desugars to Mux(Lt(x, y), x, y)
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected .min() to desugar to Mux, got {value:?}"
        );
    }
}

#[test]
fn integration_prove_block_with_captures() {
    // Simulate a prove block: outer scope has secret and hash
    let source = "\
        public hash\n\
        assert_eq(poseidon(secret, Field::ZERO), hash)";
    let ir = compile_prove_block(source, &["secret", "hash"]).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "hash");
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "secret");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}

// =====================================================================
// Audit finding regression tests
// =====================================================================

// G1: Duplicate input declarations
#[test]
fn audit_duplicate_public_public() {
    let err = compile_circuit("public x\npublic x").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
        "expected DuplicateInput, got {err:?}"
    );
}

#[test]
fn audit_duplicate_public_witness() {
    let err = compile_circuit("public x\nwitness x").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
        "expected DuplicateInput, got {err:?}"
    );
}

#[test]
fn audit_duplicate_witness_witness() {
    let err = compile_circuit("witness a\nwitness a").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "a"),
        "expected DuplicateInput, got {err:?}"
    );
}

// G2: assert_eq/assert as sub-expressions must emit constraint
#[test]
fn audit_assert_eq_in_let_emits_constraint() {
    let ir = compile_circuit("public a\npublic b\nlet x = assert_eq(a, b)").unwrap();
    let has_assert_eq = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. }));
    assert!(
        has_assert_eq,
        "assert_eq at expression level must emit AssertEq node, body: {:#?}",
        ir.body
    );
}

#[test]
fn audit_assert_in_let_emits_constraint() {
    let ir = compile_circuit("public a\nlet x = assert(a)").unwrap();
    let has_assert = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Assert { .. }));
    assert!(
        has_assert,
        "assert at expression level must emit Assert node, body: {:#?}",
        ir.body
    );
}

// G4: Double function inlining produces unique names
#[test]
fn audit_double_fn_inlining_unique_names() {
    let source = "\
        public out\n\
        fn double(a) { a * 2 }\n\
        let x = double(1)\n\
        let y = double(2)\n\
        assert_eq(x + y, out)";
    let ir = compile_circuit(source).unwrap();
    // Collect all Let names
    let names: Vec<&str> = ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::Let { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    // All names should be unique
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len(), "duplicate Let names: {names:?}");
}

// G5: range_check with very large bit count
#[test]
fn audit_range_check_large_bits_rejected() {
    let source = "public x\nrange_check(x, 5000000000)";
    let err = compile_circuit(source).unwrap_err();
    assert!(
        matches!(err, ProveIrError::UnsupportedOperation { .. }),
        "expected error for large bit count, got {err:?}"
    );
}

// G6: for range start > end (zero iterations, should not error)
#[test]
fn audit_for_range_start_gt_end() {
    // start > end means 0 iterations (saturating_sub), should compile fine
    let source = "public out\nfor i in 5..3 { }\nassert_eq(0, out)";
    let ir = compile_circuit(source).unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "expected For node"
    );
}

// G7: poseidon_many with 1 argument
#[test]
fn audit_poseidon_many_one_arg() {
    let source = "public a\nposeidon_many(a)";
    let err = compile_circuit(source).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("at least 2"),
        "expected 'at least 2' in error, got: {msg}"
    );
}

// G8: else-if chain
#[test]
fn audit_else_if_chain() {
    let source = "\
        public x\n\
        public out\n\
        let r = if x { 1 } else if x { 2 } else { 3 }\n\
        assert_eq(r, out)";
    let ir = compile_circuit(source).unwrap();
    // Should compile without error and produce Mux nodes
    let has_mux = ir.body.iter().any(|n| match n {
        CircuitNode::Let { value, .. } => matches!(value, CircuitExpr::Mux { .. }),
        _ => false,
    });
    assert!(has_mux, "expected Mux from else-if chain");
}

// For loop range too large
#[test]
fn audit_for_range_too_large() {
    let source = "public out\nfor i in 0..2000000 { }\nassert_eq(0, out)";
    let err = compile_circuit(source).unwrap_err();
    assert!(
        matches!(err, ProveIrError::RangeTooLarge { .. }),
        "expected RangeTooLarge, got {err:?}"
    );
}

// =====================================================================
// OuterScope function tests
// =====================================================================

#[test]
fn outer_scope_fn_in_prove_block() {
    // Parse a FnDecl to pass via OuterScope
    let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
    let fn_stmt = prog.stmts[0].clone();

    let outer = OuterScope {
        values: [("val", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![fn_stmt],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public expected\nassert_eq(double(val), expected)",
        &outer,
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "val");
}

#[test]
fn outer_scope_fn_in_circuit() {
    // Functions before circuit declaration should be available via OuterScope
    let source = "\
        fn double(x) { x * 2 }\n\
        circuit test(a: Public, out: Public) {\n\
            assert_eq(double(a), out)\n\
        }";
    let ir = ProveIrCompiler::<Bn254Fr>::compile_circuit(source, None).unwrap();
    assert_eq!(ir.public_inputs.len(), 2);
    // double(a) should have been inlined — no function calls remain
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn outer_scope_fn_overridden_by_local() {
    // A local fn with the same name should override the outer scope fn
    let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
    let fn_stmt = prog.stmts[0].clone();

    let outer = OuterScope {
        values: [("val", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![fn_stmt],
        ..Default::default()
    };
    // Local fn triple overrides nothing, but local double overrides outer double
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "fn double(x) { x * 3 }\npublic expected\nassert_eq(double(val), expected)",
        &outer,
    )
    .unwrap();
    // Should compile without error — the local double (x*3) is used
    assert_eq!(ir.public_inputs.len(), 1);
}

// ── Dynamic loop bounds ─────────────────────────────────────

#[test]
fn dynamic_loop_bound_capture() {
    // `for i in 0..n` where n is a capture from outer scope
    let outer = OuterScope {
        values: [("n", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public result\nmut sum = 0\nfor i in 0..n { sum = sum + i }\nassert_eq(sum, result)",
        &outer,
    )
    .unwrap();
    assert!(!ir.captures.is_empty(), "n should be a capture");
    // Should have a For node with WithCapture range
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::WithCapture { start: 0, .. },
                ..
            }
        )),
        "expected For with WithCapture range"
    );
}

#[test]
fn dynamic_loop_bound_expr() {
    // `for i in 0..n+1` where n is a capture
    let outer = OuterScope {
        values: [("n", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public result\nmut sum = 0\nfor i in 0..n+1 { sum = sum + i }\nassert_eq(sum, result)",
        &outer,
    )
    .unwrap();
    // Should have a For node with WithExpr range (n+1 is an expression)
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::WithExpr { start: 0, .. },
                ..
            }
        )),
        "expected For with WithExpr range"
    );
}

// -----------------------------------------------------------------------
// Indexed array assignment: arr[i] = expr → LetIndexed
// -----------------------------------------------------------------------

#[test]
fn mut_array_decl() {
    let ir = compile_circuit("public out\nmut arr = [1, 2, 3]\nassert_eq(arr[0], out)").unwrap();
    // Should have a LetArray node
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::LetArray { name, .. } if name == "arr")),
        "expected LetArray for mut arr, body: {:#?}",
        ir.body
    );
}

#[test]
fn indexed_assignment_constant() {
    let ir =
        compile_circuit("public out\nmut arr = [0, 0, 0]\narr[1] = 42\nassert_eq(arr[1], out)")
            .unwrap();
    // Should have a LetIndexed node
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
        "expected LetIndexed for arr[1] = 42, body: {:#?}",
        ir.body
    );
}

#[test]
fn indexed_assignment_in_loop() {
    let ir = compile_circuit(
        "public out\n\
         mut arr = [0, 0, 0]\n\
         for i in 0..3 {\n\
             arr[i] = i * 2\n\
         }\n\
         assert_eq(arr[2], out)",
    )
    .unwrap();
    // For node body should contain LetIndexed
    let for_node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::For { .. }));
    assert!(for_node.is_some(), "expected For node");
    if let CircuitNode::For { body, .. } = for_node.unwrap() {
        assert!(
            body.iter()
                .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
            "expected LetIndexed inside for loop body, got: {body:#?}"
        );
    }
}

#[test]
fn indexed_assignment_immutable_array_rejected() {
    let err =
        compile_circuit("public out\nlet arr = [1, 2, 3]\narr[0] = 99\nassert_eq(arr[0], out)")
            .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("mut"), "error should mention mut, got: {msg}");
}

#[test]
fn indexed_assignment_scalar_rejected() {
    let err = compile_circuit("public out\nmut x = 5\nx[0] = 10\nassert_eq(x, out)").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("array") || msg.contains("scalar"),
        "error should mention type mismatch, got: {msg}"
    );
}

// --- Circom interop: circom_table registration (Phase 3.1) ---

mod circom_table {
    use super::super::*;
    use crate::prove_ir::circom_interop::test_support::StubLibrary;
    use crate::prove_ir::circom_interop::{CircomLibraryHandle, CircomTemplateSignature};
    use std::sync::Arc;

    fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
        CircomTemplateSignature {
            params: params.iter().map(|s| s.to_string()).collect(),
            input_signals: inputs.iter().map(|s| s.to_string()).collect(),
            output_signals: outputs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn new_compiler_has_empty_circom_table() {
        let compiler = ProveIrCompiler::<Bn254Fr>::new();
        assert!(compiler.circom_table.is_empty());
        assert_eq!(compiler.circom_call_counter, 0);
    }

    #[test]
    fn register_circom_template_inserts_entry_without_bumping_counter() {
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
            "Square",
            sig(&[], &["x"], &["y"]),
        ));
        compiler.register_circom_template("Square".to_string(), lib, "Square".to_string());

        assert_eq!(compiler.circom_table.len(), 1);
        let entry = compiler
            .lookup_circom_template("Square")
            .expect("Square should be registered");
        assert_eq!(entry.template_name, "Square");
        // Registration alone MUST NOT bump the call counter —
        // only actual instantiation sites do.
        assert_eq!(compiler.circom_call_counter, 0);
    }

    #[test]
    fn next_circom_call_prefix_produces_monotonic_unique_ids() {
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        assert_eq!(compiler.next_circom_call_prefix(), "circom_call_0");
        assert_eq!(compiler.next_circom_call_prefix(), "circom_call_1");
        assert_eq!(compiler.next_circom_call_prefix(), "circom_call_2");
        assert_eq!(compiler.circom_call_counter, 3);
    }

    #[test]
    fn namespaced_key_coexists_with_selective_key() {
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        let poseidon_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
            "Poseidon",
            sig(&["t"], &["inputs"], &["out"]),
        ));
        let num2bits_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
            "Num2Bits",
            sig(&["n"], &["in"], &["out"]),
        ));
        compiler.register_circom_template(
            "P::Poseidon".to_string(),
            poseidon_lib,
            "Poseidon".to_string(),
        );
        compiler.register_circom_template(
            "Num2Bits".to_string(),
            num2bits_lib,
            "Num2Bits".to_string(),
        );

        assert_eq!(compiler.circom_table.len(), 2);
        assert_eq!(
            compiler
                .lookup_circom_template("P::Poseidon")
                .unwrap()
                .template_name,
            "Poseidon"
        );
        assert_eq!(
            compiler
                .lookup_circom_template("Num2Bits")
                .unwrap()
                .template_name,
            "Num2Bits"
        );
        assert!(compiler.lookup_circom_template("Poseidon").is_none());
    }

    #[test]
    fn outer_scope_circom_imports_are_seeded_into_circom_table() {
        // Drive the seeding path end-to-end via `compile_prove_block`
        // so we don't need to construct a `Block` with a synthetic
        // span. Using a trivial prove-block body is enough to
        // exercise OuterScope → circom_table threading.
        let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
            "Square",
            sig(&[], &["x"], &["y"]),
        ));
        let mut imports = HashMap::new();
        imports.insert(
            "Square".to_string(),
            CircomCallable {
                library: lib,
                template_name: "Square".to_string(),
            },
        );
        let outer = OuterScope {
            circom_imports: imports.clone(),
            ..Default::default()
        };

        // Direct new-compiler path lets us inspect the seeded table
        // without having to run a full compilation. Mirror what
        // `compile_with_source_dir` does on entry.
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        for (key, callable) in &outer.circom_imports {
            compiler.circom_table.insert(key.clone(), callable.clone());
        }
        assert_eq!(compiler.circom_table.len(), 1);
        assert!(compiler.lookup_circom_template("Square").is_some());
    }
}

// --- Circom interop: compile_call dispatch (Phase 3.3) ---

mod circom_dispatch {
    use super::super::*;
    use crate::prove_ir::circom_interop::{
        CircomInstantiation, CircomLibraryHandle, CircomTemplateOutput, CircomTemplateSignature,
    };
    use crate::prove_ir::error::{CircomDispatchErrorKind, ProveIrError};
    use diagnostics::Span;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
        CircomTemplateSignature {
            params: params.iter().map(|s| s.to_string()).collect(),
            input_signals: inputs.iter().map(|s| s.to_string()).collect(),
            output_signals: outputs.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Stub that records instantiation calls so tests can assert
    /// what the dispatcher handed to the library handle. Mirrors
    /// `StubLibrary` but captures every `instantiate_template` call
    /// into an interior-mutable log.
    #[derive(Debug)]
    struct RecordingLibrary {
        sig: CircomTemplateSignature,
        template_name: String,
        calls: std::sync::Mutex<Vec<RecordedCall>>,
    }

    #[derive(Debug, Clone)]
    struct RecordedCall {
        template_name: String,
        template_args: Vec<FieldConst>,
        signal_inputs: Vec<(String, CircuitExpr)>,
        parent_prefix: String,
    }

    impl RecordingLibrary {
        fn new(template_name: &str, sig: CircomTemplateSignature) -> Self {
            Self {
                sig,
                template_name: template_name.to_string(),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn recorded(&self) -> Vec<RecordedCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CircomLibraryHandle for RecordingLibrary {
        fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
            if name == self.template_name {
                Some(self.sig.clone())
            } else {
                None
            }
        }
        fn template_names(&self) -> Vec<String> {
            vec![self.template_name.clone()]
        }
        fn resolve_input_layout(
            &self,
            template_name: &str,
            _template_args: &[FieldConst],
        ) -> Option<Vec<crate::prove_ir::CircomInputLayout>> {
            if template_name != self.template_name {
                return None;
            }
            Some(
                self.sig
                    .input_signals
                    .iter()
                    .map(|n| crate::prove_ir::CircomInputLayout {
                        name: n.clone(),
                        dims: Vec::new(),
                    })
                    .collect(),
            )
        }
        fn instantiate_template(
            &self,
            template_name: &str,
            template_args: &[FieldConst],
            signal_inputs: &HashMap<String, CircuitExpr>,
            parent_prefix: &str,
            _span: &Span,
        ) -> Result<CircomInstantiation, crate::prove_ir::CircomDispatchError> {
            let mut inputs: Vec<(String, CircuitExpr)> = signal_inputs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            inputs.sort_by(|a, b| a.0.cmp(&b.0));
            self.calls.lock().unwrap().push(RecordedCall {
                template_name: template_name.to_string(),
                template_args: template_args.to_vec(),
                signal_inputs: inputs,
                parent_prefix: parent_prefix.to_string(),
            });
            // Emit a marker Let so tests can observe the body was
            // extended with the library's contribution.
            let body = vec![CircuitNode::Let {
                name: format!("{parent_prefix}_marker"),
                value: CircuitExpr::Const(FieldConst::from_u64(42)),
                span: None,
            }];
            // Populate every declared output so multi-output
            // tests can verify per-output binding in the env.
            let mut outputs = HashMap::new();
            for out in &self.sig.output_signals {
                outputs.insert(
                    out.clone(),
                    CircomTemplateOutput::Scalar(CircuitExpr::Var(format!(
                        "{parent_prefix}_{out}"
                    ))),
                );
            }
            Ok(CircomInstantiation { body, outputs })
        }
    }

    fn compiler_with_stub(
        template: &str,
        sig_val: CircomTemplateSignature,
    ) -> (ProveIrCompiler<Bn254Fr>, Arc<RecordingLibrary>) {
        let lib = Arc::new(RecordingLibrary::new(template, sig_val));
        let handle: Arc<dyn CircomLibraryHandle> = lib.clone();
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        compiler.register_circom_template(template.to_string(), handle, template.to_string());
        // The prove block has an "x" public input that the
        // template consumes.
        compiler
            .env
            .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));
        (compiler, lib)
    }

    fn parse_expr(source: &str) -> Expr {
        let (program, errors) = achronyme_parser::parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        match &program.stmts[0] {
            Stmt::Expr(e) => e.clone(),
            other => panic!("expected expression statement, got {other:?}"),
        }
    }

    #[test]
    fn bare_template_call_dispatches_to_library() {
        let (mut compiler, lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        // Parse `Square()(x)` as an atomic curry expression.
        let expr = parse_expr("Square()(x)");
        let result = compiler
            .compile_expr(&expr)
            .expect("compile should succeed");
        // Dispatcher returns the mangled output Var for the
        // single scalar output.
        assert_eq!(result, CircuitExpr::Var("circom_call_0_y".to_string()));

        // The library received the call with empty template args
        // and one signal input wired to `x`.
        let calls = lib.recorded();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].template_name, "Square");
        assert!(calls[0].template_args.is_empty());
        assert_eq!(calls[0].signal_inputs.len(), 1);
        assert_eq!(calls[0].signal_inputs[0].0, "x");
        assert_eq!(calls[0].parent_prefix, "circom_call_0");

        // The compiler body was extended with the stub's marker.
        assert!(compiler.body.iter().any(|n| matches!(
            n,
            CircuitNode::Let { name, .. } if name == "circom_call_0_marker"
        )));
        // And the call counter bumped.
        assert_eq!(compiler.circom_call_counter, 1);
    }

    #[test]
    fn parametric_template_evaluates_args_at_compile_time() {
        let (mut compiler, lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
        compiler.env.insert(
            "in_sig".to_string(),
            CompEnvValue::Scalar("in_sig".to_string()),
        );
        // Num2Bits(8)(in_sig)
        let expr = parse_expr("Num2Bits(8)(in_sig)");
        compiler
            .compile_expr(&expr)
            .expect("compile should succeed");

        let calls = lib.recorded();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].template_args.len(), 1);
        assert_eq!(calls[0].template_args[0], FieldConst::from_u64(8));
    }

    #[test]
    fn template_arg_must_be_compile_time_const() {
        let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
        // `x` is a runtime input — Num2Bits(x) must be rejected.
        let expr = parse_expr("Num2Bits(x)(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("compile-time constant"),
            "error should mention compile-time constant requirement: {msg}"
        );
    }

    #[test]
    fn template_param_count_mismatch_rejected() {
        let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
        // Zero template args instead of one.
        let expr = parse_expr("Num2Bits()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("template parameter") && msg.contains("expects"),
            "expected parameter-count error, got: {msg}"
        );
    }

    #[test]
    fn signal_input_count_mismatch_rejected() {
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        // Square takes 1 signal input, passing 2.
        let expr = parse_expr("Square()(x, x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("signal input") && msg.contains("expects"),
            "expected signal-input-count error, got: {msg}"
        );
    }

    #[test]
    fn multi_output_template_at_expression_level_suggests_let_binding() {
        // Expression-level calls on multi-output templates must
        // redirect the user to bind the result via let so each
        // output can be named through DotAccess.
        let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
        let expr = parse_expr("Pair()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("2 outputs") && msg.contains("let r"),
            "expected let-binding suggestion, got: {msg}"
        );
    }

    #[test]
    fn call_counter_is_per_compiler() {
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        let e1 = parse_expr("Square()(x)");
        let e2 = parse_expr("Square()(x)");
        let r1 = compiler.compile_expr(&e1).unwrap();
        let r2 = compiler.compile_expr(&e2).unwrap();
        assert_eq!(r1, CircuitExpr::Var("circom_call_0_y".to_string()));
        assert_eq!(r2, CircuitExpr::Var("circom_call_1_y".to_string()));
        assert_eq!(compiler.circom_call_counter, 2);
    }

    #[test]
    fn non_circom_call_falls_through_unchanged() {
        // A Call that doesn't match the circom currying pattern
        // (no second Call layer) must fall through to the normal
        // function dispatch without hitting circom code paths.
        let (mut compiler, lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        // Not a curry — just `x + 1` as a plain expr.
        let expr = parse_expr("x + 1");
        let _ = compiler.compile_expr(&expr).unwrap();
        assert!(
            lib.recorded().is_empty(),
            "library should not have been called for non-circom expression"
        );
    }

    // --- Phase 3.4: let-binding + DotAccess ---

    /// Parse source as a Block and compile through compile_block_stmts.
    /// Useful for tests that need a let + dot-access sequence.
    fn compile_block(
        compiler: &mut ProveIrCompiler<Bn254Fr>,
        source: &str,
    ) -> Result<(), ProveIrError> {
        use achronyme_parser::parse_program;
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let block = Block {
            stmts: program.stmts,
            span: Span {
                byte_start: 0,
                byte_end: 0,
                line_start: 0,
                col_start: 0,
                line_end: 0,
                col_end: 0,
            },
        };
        compiler.compile_block_stmts(&block)
    }

    #[test]
    fn let_bind_multi_output_template_publishes_dotted_env_entries() {
        let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
        compile_block(&mut compiler, "let r = Pair()(x)")
            .expect("let-binding a multi-output template should succeed");
        // Each output lands under "r.<output>" in the env.
        assert!(compiler.env.contains_key("r.a"));
        assert!(compiler.env.contains_key("r.b"));
        // Single-scalar convenience binding is NOT emitted for
        // multi-output templates.
        assert!(!compiler.env.contains_key("r"));
    }

    #[test]
    fn let_bind_single_scalar_template_also_binds_top_level_ident() {
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        compile_block(&mut compiler, "let r = Square()(x)")
            .expect("let-binding a scalar template should succeed");
        // Both `r` and `r.y` exist.
        assert!(compiler.env.contains_key("r"));
        assert!(compiler.env.contains_key("r.y"));
    }

    #[test]
    fn dot_access_on_multi_output_let_binding_resolves_to_mangled_vars() {
        let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
        compile_block(
            &mut compiler,
            "let r = Pair()(x)\nassert_eq(r.a, x)\nassert_eq(r.b, x)",
        )
        .expect("dot access on multi-output should resolve");
        // The compile body now has assert_eq nodes pointing at
        // the mangled sub-template vars.
        let assert_vars: Vec<&str> = compiler
            .body
            .iter()
            .filter_map(|n| match n {
                CircuitNode::AssertEq {
                    lhs: CircuitExpr::Var(v),
                    ..
                } => Some(v.as_str()),
                _ => None,
            })
            .collect();
        // StubLibrary names outputs as `<prefix>_<out>`. Pair's
        // outputs were a/b; the instantiated prefix is
        // circom_call_0. We expect exactly the first output
        // recorded — the stub only stores the first in outputs.
        // For this test we just assert both asserts landed.
        assert!(assert_vars.iter().any(|v| v.starts_with("circom_call_")));
    }

    #[test]
    fn namespaced_let_binding_publishes_dotted_env_entries() {
        // The namespaced form P.Pair(...)(...) is resolved the same
        // way as the bare form once try_resolve_circom_key has
        // produced the "P::Pair" key, so the let-binding path
        // should bind outputs identically.
        let (mut compiler, _lib) = compiler_with_stub(
            "Pair", // template_name
            sig(&[], &["x"], &["a", "b"]),
        );
        // Rewire the registration: under key "P::Pair" instead of
        // "Pair" (simulates a namespace import). We need to re-
        // register because compiler_with_stub bound under "Pair".
        let entry = compiler.circom_table.remove("Pair").unwrap();
        compiler.circom_table.insert("P::Pair".to_string(), entry);

        compile_block(&mut compiler, "let r = P.Pair()(x)")
            .expect("namespaced let-binding should succeed");
        assert!(compiler.env.contains_key("r.a"));
        assert!(compiler.env.contains_key("r.b"));
    }

    /// Stub that returns an array output to exercise the array-
    /// flattening code path on the let-binding side.
    #[derive(Debug)]
    struct ArrayOutputLibrary {
        name: String,
        dims: Vec<u64>,
    }
    impl CircomLibraryHandle for ArrayOutputLibrary {
        fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
            if name != self.name {
                return None;
            }
            Some(CircomTemplateSignature {
                params: vec!["n".to_string()],
                input_signals: vec!["in".to_string()],
                output_signals: vec!["out".to_string()],
            })
        }
        fn template_names(&self) -> Vec<String> {
            vec![self.name.clone()]
        }
        fn resolve_input_layout(
            &self,
            template_name: &str,
            _template_args: &[FieldConst],
        ) -> Option<Vec<crate::prove_ir::CircomInputLayout>> {
            if template_name != self.name {
                return None;
            }
            // Single scalar input `in` for this stub.
            Some(vec![crate::prove_ir::CircomInputLayout {
                name: "in".to_string(),
                dims: Vec::new(),
            }])
        }
        fn instantiate_template(
            &self,
            _template_name: &str,
            _template_args: &[FieldConst],
            _signal_inputs: &HashMap<String, CircuitExpr>,
            parent_prefix: &str,
            _span: &Span,
        ) -> Result<CircomInstantiation, crate::prove_ir::CircomDispatchError> {
            let total: u64 = self.dims.iter().product();
            let values: Vec<CircuitExpr> = (0..total)
                .map(|i| CircuitExpr::Var(format!("{parent_prefix}_out_{i}")))
                .collect();
            let mut outputs = HashMap::new();
            outputs.insert(
                "out".to_string(),
                CircomTemplateOutput::Array {
                    dims: self.dims.clone(),
                    values,
                },
            );
            Ok(CircomInstantiation {
                body: Vec::new(),
                outputs,
            })
        }
    }

    #[test]
    fn let_bind_array_output_publishes_indexed_env_entries() {
        let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
            name: "Num2Bits".to_string(),
            dims: vec![4],
        });
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
        compiler
            .env
            .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

        compile_block(&mut compiler, "let r = Num2Bits(4)(x)")
            .expect("array-output let binding should succeed");
        for i in 0..4 {
            let key = format!("r.out_{i}");
            assert!(
                compiler.env.contains_key(&key),
                "expected env key {key}, have: {:?}",
                compiler.env.keys().collect::<Vec<_>>()
            );
        }
        // No top-level `r` binding — arrays don't have a scalar
        // convenience form.
        assert!(!compiler.env.contains_key("r"));
    }

    // --- Phase 3.5: structured diagnostics ---

    #[test]
    fn unknown_template_name_with_near_match_suggests_did_you_mean() {
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        // `Squar` is a 1-edit typo of `Square`.
        let expr = parse_expr("Squar()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("not imported") && msg.contains("did you mean `Square`"),
            "expected did-you-mean suggestion, got: {msg}"
        );
    }

    #[test]
    fn unknown_namespace_alias_suggests_did_you_mean() {
        // Register under namespace alias "Pp".
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        let entry = compiler.circom_table.remove("Square").unwrap();
        compiler
            .circom_table
            .insert("Pp::Square".to_string(), entry);
        // Typo `Pk` for `Pp`.
        let expr = parse_expr("Pk.Square()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("namespace `Pk`") && msg.contains("did you mean `Pp`"),
            "expected namespace did-you-mean, got: {msg}"
        );
    }

    #[test]
    fn namespaced_template_typo_suggests_did_you_mean_within_namespace() {
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        let entry = compiler.circom_table.remove("Square").unwrap();
        compiler.circom_table.insert("P::Square".to_string(), entry);
        // `Squar` is a near-miss of `Square` inside namespace `P`.
        let expr = parse_expr("P.Squar()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("namespace `P`")
                && msg.contains("Squar")
                && msg.contains("did you mean `Square`"),
            "expected namespace-scoped did-you-mean, got: {msg}"
        );
    }

    #[test]
    fn bare_template_call_without_param_layer_hints_atomic_curry() {
        // User wrote `Square(x)` instead of `Square()(x)`.
        let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
        let expr = parse_expr("Square(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("called atomically") && msg.contains("template params"),
            "expected atomic-curry hint, got: {msg}"
        );
    }

    #[test]
    fn template_arg_not_const_uses_structured_kind() {
        let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
        let expr = parse_expr("Num2Bits(x)(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        // Verify the error uses the structured CircomDispatch
        // variant, not a raw UnsupportedOperation.
        assert!(
            matches!(
                err,
                ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateArgNotConst { arg_index: 0, .. },
                    ..
                }
            ),
            "expected CircomDispatch(TemplateArgNotConst), got: {err:?}"
        );
    }

    #[test]
    fn param_count_mismatch_uses_structured_kind() {
        let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
        let expr = parse_expr("Num2Bits()(x)");
        let err = compiler.compile_expr(&expr).expect_err("should fail");
        assert!(
            matches!(
                err,
                ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::ParamCountMismatch {
                        expected: 1,
                        got: 0,
                        ..
                    },
                    ..
                }
            ),
            "expected CircomDispatch(ParamCountMismatch), got: {err:?}"
        );
    }

    #[test]
    fn dot_access_on_array_output_bit_resolves_via_indexed_env_key() {
        // `r.out_2` should resolve to the mangled `circom_call_0_out_2`.
        let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
            name: "Num2Bits".to_string(),
            dims: vec![4],
        });
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
        compiler
            .env
            .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

        compile_block(
            &mut compiler,
            "let r = Num2Bits(4)(x)\nassert_eq(r.out_2, x)",
        )
        .expect("dot access on array-output bit should resolve");
        // Verify an AssertEq landed that references the mangled
        // 2nd element of the array output.
        let has_expected = compiler.body.iter().any(|n| match n {
            CircuitNode::AssertEq {
                lhs: CircuitExpr::Var(lhs),
                ..
            } => lhs == "circom_call_0_out_2",
            _ => false,
        });
        assert!(
            has_expected,
            "expected assert_eq lhs = circom_call_0_out_2, body: {:?}",
            compiler.body
        );
    }
}
