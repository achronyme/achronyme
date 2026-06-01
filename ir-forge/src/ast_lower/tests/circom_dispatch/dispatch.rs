use super::*;

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
