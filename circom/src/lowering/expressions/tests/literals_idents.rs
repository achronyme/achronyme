use super::*;

// ── Literals ────────────────────────────────────────────────────

#[test]
fn lower_decimal_number() {
    let expr = parse_expr("42");
    let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
    assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
}

#[test]
fn lower_hex_number() {
    let expr = parse_expr("0xFF");
    let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
    assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(255)));
}

#[test]
fn lower_zero() {
    let expr = parse_expr("0");
    let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
    assert_eq!(result, CircuitExpr::Const(FieldConst::zero()));
}

// ── Identifiers ─────────────────────────────────────────────────

#[test]
fn lower_input_ident() {
    let expr = parse_expr("a");
    assert_eq!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Input("a".to_string())
    );
}

#[test]
fn lower_local_ident() {
    let expr = parse_expr("x");
    assert_eq!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Var("x".to_string())
    );
}

#[test]
fn lower_capture_ident() {
    let expr = parse_expr("n");
    assert_eq!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Capture("n".to_string())
    );
}

#[test]
fn lower_placeholder_loop_var_emits_loopvar_node() {
    // memoized unroll: when the lowering context carries an
    // active memoization placeholder, an `Ident` matching that name
    // resolves to `CircuitExpr::LoopVar(token)` regardless of what
    // `env.known_constants` or `env.resolve` would otherwise say.
    // The test asserts the placeholder takes precedence over the
    // const-fold path that would normally fold `i` to `Const(0)`
    // (the canonical legacy unroll behaviour for iter 0).
    let expr = parse_expr("i");
    let mut env = make_env();
    // Seed the legacy unroll state too — `placeholder_loop_var`
    // must override it so the regimes don't have to coordinate
    // env mutations.
    env.known_constants
        .insert("i".to_string(), FieldConst::from_u64(0));

    let mut ctx = make_ctx();
    ctx.placeholder_loop_var = Some(("i".to_string(), 7));

    assert_eq!(
        lower_expr(&expr, &env, &mut ctx).unwrap(),
        CircuitExpr::LoopVar(7),
    );
}

#[test]
fn lower_placeholder_signal_array_index_produces_arrayindex_loopvar() {
    // The full Option D contract: with the placeholder active, an
    // `arr[i]` read where `arr` is a registered signal array
    // skips the const-fold-then-resolve_array_element fast path
    // (because `i` is no longer in `known_constants`) and lands
    // in the symbolic fall-through that emits
    // `ArrayIndex { array, index: LoopVar(t) }`. After
    // `substitute_loop_var(slice, t, N)` the index becomes
    // `Const(N)` and instantiate's existing fast path resolves
    // `arr_N` from the env's `InstEnvValue::Array`.
    let expr = parse_expr("arr[i]");
    let mut env = make_env();
    env.register_array("arr".to_string(), 4);
    for i in 0..4 {
        env.locals.insert(format!("arr_{i}"));
    }

    let mut ctx = make_ctx();
    ctx.placeholder_loop_var = Some(("i".to_string(), 7));

    let lowered = lower_expr(&expr, &env, &mut ctx).unwrap();
    match lowered {
        CircuitExpr::ArrayIndex { array, index } => {
            assert_eq!(array, "arr");
            assert_eq!(*index, CircuitExpr::LoopVar(7));
        }
        other => panic!("expected ArrayIndex {{ array, index: LoopVar(7) }}, got {other:?}",),
    }
}

#[test]
fn lower_placeholder_does_not_affect_other_idents() {
    // Sanity: only the named placeholder ident takes the LoopVar
    // branch. Other idents still resolve via the env (`a` is an
    // input in `make_env`).
    let expr = parse_expr("a");
    let env = make_env();
    let mut ctx = make_ctx();
    ctx.placeholder_loop_var = Some(("i".to_string(), 7));

    assert_eq!(
        lower_expr(&expr, &env, &mut ctx).unwrap(),
        CircuitExpr::Input("a".to_string()),
    );
}

#[test]
fn lower_undefined_ident_is_error() {
    let expr = parse_expr("unknown");
    let result = lower_expr(&expr, &make_env(), &mut make_ctx());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .diagnostic
        .message
        .contains("undefined variable"));
}
