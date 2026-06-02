use std::collections::HashMap;

use super::*;
use crate::types::{CircuitBinOp, FieldConst};

#[test]
fn mangle_name_format() {
    assert_eq!(mangle_name("c", "a"), "c.a");
    assert_eq!(mangle_name("comp", "signal"), "comp.signal");
}

#[test]
fn mangle_expr_input_becomes_var() {
    let expr = CircuitExpr::Input("a".to_string());
    let result = mangle_expr(&expr, "c", &HashMap::new());
    assert_eq!(result, CircuitExpr::Var("c.a".to_string()));
}

#[test]
fn mangle_expr_var_prefixed() {
    let expr = CircuitExpr::Var("x".to_string());
    let result = mangle_expr(&expr, "c", &HashMap::new());
    assert_eq!(result, CircuitExpr::Var("c.x".to_string()));
}

#[test]
fn mangle_expr_capture_substituted() {
    let mut subs = HashMap::new();
    subs.insert("n".to_string(), CircuitExpr::Const(FieldConst::from_u64(8)));
    let expr = CircuitExpr::Capture("n".to_string());
    let result = mangle_expr(&expr, "c", &subs);
    assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(8)));
}

#[test]
fn mangle_expr_const_unchanged() {
    let expr = CircuitExpr::Const(FieldConst::from_u64(42));
    let result = mangle_expr(&expr, "c", &HashMap::new());
    assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
}

#[test]
fn mangle_node_let() {
    let node = CircuitNode::Let {
        name: "x".to_string(),
        value: CircuitExpr::Input("a".to_string()),
        span: None,
    };
    let result = mangle_node(&node, "c", &HashMap::new());
    match result {
        CircuitNode::Let { name, value, .. } => {
            assert_eq!(name, "c.x");
            assert_eq!(value, CircuitExpr::Var("c.a".to_string()));
        }
        _ => panic!("expected Let"),
    }
}

#[test]
fn mangle_node_assert_eq() {
    let node = CircuitNode::AssertEq {
        lhs: CircuitExpr::Var("out".to_string()),
        rhs: CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Input("a".to_string())),
            rhs: Box::new(CircuitExpr::Input("b".to_string())),
        },
        message: None,
        span: None,
    };
    let result = mangle_node(&node, "m", &HashMap::new());
    match result {
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            assert_eq!(lhs, CircuitExpr::Var("m.out".to_string()));
            match rhs {
                CircuitExpr::BinOp { lhs, rhs, .. } => {
                    assert_eq!(*lhs, CircuitExpr::Var("m.a".to_string()));
                    assert_eq!(*rhs, CircuitExpr::Var("m.b".to_string()));
                }
                _ => panic!("expected BinOp"),
            }
        }
        _ => panic!("expected AssertEq"),
    }
}

#[test]
fn mangle_for_range_literal_unchanged() {
    let range = ForRange::Literal { start: 0, end: 8 };
    let result = mangle_range(&range, "c", &HashMap::new());
    assert_eq!(result, ForRange::Literal { start: 0, end: 8 });
}

#[test]
fn mangle_for_range_capture_with_known_const() {
    let mut subs = HashMap::new();
    subs.insert(
        "n".to_string(),
        CircuitExpr::Const(FieldConst::from_u64(16)),
    );
    let range = ForRange::WithCapture {
        start: 0,
        end_capture: "n".to_string(),
    };
    let result = mangle_range(&range, "c", &subs);
    assert_eq!(result, ForRange::Literal { start: 0, end: 16 });
}

/// Nested `ComponentCall` composition: applying an outer prefix to
/// a body that already holds a deferred inner instance must prefix
/// the inner instance name and mangle its substitution expressions,
/// while leaving the content-addressed `body_key` untouched. This
/// is the invariant that makes deferred expansion equivalent to
/// eager inlining.
#[test]
fn mangle_nested_component_call_composes_prefix() {
    let inner = CircuitNode::ComponentCall {
        body_key: "Inner:n=4".to_string(),
        comp_name: "sub_0".to_string(),
        param_subs: vec![("n".to_string(), CircuitExpr::Var("acc".to_string()))],
        span: None,
    };
    let result = mangle_node(&inner, "outer_3", &HashMap::new());
    match result {
        CircuitNode::ComponentCall {
            body_key,
            comp_name,
            param_subs,
            ..
        } => {
            assert_eq!(body_key, "Inner:n=4", "content key is prefix-independent");
            assert_eq!(comp_name, "outer_3.sub_0");
            assert_eq!(param_subs.len(), 1);
            assert_eq!(param_subs[0].0, "n");
            assert_eq!(
                param_subs[0].1,
                CircuitExpr::Var("outer_3.acc".to_string()),
                "substitution expressions are mangled with the outer prefix"
            );
        }
        _ => panic!("expected ComponentCall"),
    }
}
