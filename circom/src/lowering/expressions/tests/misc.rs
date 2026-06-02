use super::*;

// ── Parallel is transparent ─────────────────────────────────────

#[test]
fn lower_parallel_is_transparent() {
    let expr = parse_expr("parallel a");
    assert_eq!(
        lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
        CircuitExpr::Input("a".to_string())
    );
}

// ── Large number literals ────────────────────────────────────────

#[test]
fn lower_large_decimal_number() {
    let expr =
        parse_expr("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::Const(fc) => {
            assert!(fc.to_u64().is_none());
            assert!(!fc.is_zero());
        }
        other => panic!("expected Const, got {:?}", other),
    }
}

#[test]
fn lower_large_hex_number() {
    let expr = parse_expr("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
    match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
        CircuitExpr::Const(fc) => assert!(fc.to_u64().is_none()),
        other => panic!("expected Const, got {:?}", other),
    }
}

// ── const_eval_u64 (moved to utils, verify still works) ─────────

#[test]
fn const_eval_decimal() {
    assert_eq!(const_eval_u64(&parse_expr("42")), Some(42));
}

#[test]
fn const_eval_hex() {
    assert_eq!(const_eval_u64(&parse_expr("0x10")), Some(16));
}

#[test]
fn const_eval_non_const() {
    assert_eq!(const_eval_u64(&parse_expr("a + 1")), None);
}

#[test]
fn nested_dot_access_error() {
    let expr = parse_expr("c.sub.x");
    let mut env = make_env();
    env.locals.insert("c.sub".to_string());
    let result = lower_expr(&expr, &env, &mut make_ctx());
    assert!(result.is_err());
    let msg = result.unwrap_err().diagnostic.message;
    assert!(
        msg.contains("dot access target"),
        "expected dot access error, got: {msg}"
    );
}
