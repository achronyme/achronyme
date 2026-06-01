use super::*;

// --- structured diagnostics ---

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
