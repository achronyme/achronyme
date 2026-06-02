use std::collections::{HashMap, HashSet};

use artik::{ElemT, RegType};

use super::super::ConstInt;
use super::*;
use crate::ast::{Definition, FunctionDef, Stmt};
use crate::parser::parse_circom;

fn parse_body(body_src: &str) -> Vec<Stmt> {
    let src = format!("function probe(c, x, n, a, cond) {{ {body_src} }}");
    let (prog, errors) = parse_circom(&src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    match &prog.definitions[0] {
        Definition::Function(f) => f.body.stmts.clone(),
        _ => panic!("expected function"),
    }
}

fn shape(body_src: &str) -> CalleeReturnShape {
    infer_callee_return_shape(
        &parse_body(body_src),
        &HashMap::new(),
        &HashMap::new(),
        &mut HashSet::new(),
    )
}

fn shape_with(body_src: &str, consts: &[(&str, ConstInt)]) -> CalleeReturnShape {
    let map: HashMap<String, ConstInt> = consts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    infer_callee_return_shape(
        &parse_body(body_src),
        &map,
        &HashMap::new(),
        &mut HashSet::new(),
    )
}

/// Parse a source holding several `function` definitions and
/// classify the return shape of `entry`'s body against a registry
/// of all the others — exercises forwarded-call return resolution.
fn shape_multi(src: &str, entry: &str) -> CalleeReturnShape {
    let (prog, errors) = parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let mut funcs: HashMap<String, &FunctionDef> = HashMap::new();
    for def in &prog.definitions {
        if let Definition::Function(f) = def {
            funcs.insert(f.name.clone(), f);
        }
    }
    let body = funcs
        .get(entry)
        .unwrap_or_else(|| panic!("no function {entry}"))
        .body
        .stmts
        .clone();
    infer_callee_return_shape(&body, &HashMap::new(), &funcs, &mut HashSet::new())
}

#[test]
fn scalar_returns_classify_as_scalar() {
    assert_eq!(shape("return 1 + 2;"), CalleeReturnShape::Scalar);
    assert_eq!(shape("var x = 3; return x;"), CalleeReturnShape::Scalar);
    assert_eq!(shape("return a[0];"), CalleeReturnShape::Scalar);
}

#[test]
fn array_literal_and_decl_returns_classify_as_array() {
    assert_eq!(shape("return [1, 2, 3];"), CalleeReturnShape::Array(3));
    assert_eq!(
        shape("var out[4]; return out;"),
        CalleeReturnShape::Array(4)
    );
}

#[test]
fn array_decl_dim_folds_against_param_consts() {
    assert_eq!(
        shape_with("var out[n]; return out;", &[("n", 5)]),
        CalleeReturnShape::Array(5)
    );
}

#[test]
fn two_dimensional_decl_returns_classify_as_array2d() {
    assert_eq!(
        shape("var m[2][3]; return m;"),
        CalleeReturnShape::Array2D(2, 3)
    );
}

#[test]
fn return_count_does_not_force_other() {
    // A single top-level array return is `Other` for the inlining
    // path's slot heuristic; for a subprogram it is a real
    // `Return`, so it must classify cleanly.
    assert_eq!(
        shape("var out[2]; return out;"),
        CalleeReturnShape::Array(2)
    );
    assert_eq!(
        shape("if (c) { var out[2]; return out; } var r[2]; return r;"),
        CalleeReturnShape::Array(2)
    );
}

#[test]
fn disagreeing_return_shapes_are_other() {
    assert_eq!(
        shape("if (c) { return 1; } var out[2]; return out;"),
        CalleeReturnShape::Other
    );
    assert_eq!(
        shape("if (c) { var a[2]; return a; } var b[3]; return b;"),
        CalleeReturnShape::Other
    );
}

#[test]
fn forwarded_call_return_to_unknown_callee_is_other() {
    // No registry entry for `foo`: shape is unresolvable.
    assert_eq!(shape("return foo(x);"), CalleeReturnShape::Other);
}

#[test]
fn forwarded_scalar_call_return_resolves_to_scalar() {
    // `fwd` ends `return leaf(x);`; `leaf` returns a scalar, so
    // `fwd`'s return shape is that scalar.
    assert_eq!(
        shape_multi(
            "function leaf(a) { return a + 1; } \
             function fwd(x) { return leaf(x); }",
            "fwd",
        ),
        CalleeReturnShape::Scalar
    );
}

#[test]
fn forwarded_call_in_ternary_reuses_callee_across_branches() {
    // Both ternary arms forward to the same callee. The visited
    // set must be cleared between arms so the second resolves
    // (a true cycle is the only thing that should trip the guard).
    assert_eq!(
        shape_multi(
            "function leaf(a) { return a + 1; } \
             function fwd(c, x, y) { return c == 0 ? leaf(x) : leaf(y); }",
            "fwd",
        ),
        CalleeReturnShape::Scalar
    );
}

#[test]
fn forwarded_array_call_return_declines() {
    // `leaf` returns an array; a forwarded array return is not
    // deliverable by the scalar-result emission, so it declines
    // (Other) rather than reserving an undeliverable shape.
    assert_eq!(
        shape_multi(
            "function leaf(a) { var o[3]; return o; } \
             function fwd(x) { return leaf(x); }",
            "fwd",
        ),
        CalleeReturnShape::Other
    );
}

#[test]
fn forwarded_call_arity_mismatch_declines() {
    assert_eq!(
        shape_multi(
            "function leaf(a, b) { return a + b; } \
             function fwd(x) { return leaf(x); }",
            "fwd",
        ),
        CalleeReturnShape::Other
    );
}

#[test]
fn runtime_dim_array_is_other() {
    // `n` is not in param_consts, so the dim does not fold.
    assert_eq!(shape("var out[n]; return out;"), CalleeReturnShape::Other);
}

#[test]
fn scalar_ternary_returns_classify_as_scalar() {
    assert_eq!(
        shape("return cond == 0 ? 1 : x;"),
        CalleeReturnShape::Scalar
    );
}

fn dim_sig(body_src: &str) -> Option<Vec<u32>> {
    compute_dim_signature(&parse_body(body_src), &HashMap::new())
}

fn dim_sig_with(body_src: &str, consts: &[(&str, ConstInt)]) -> Option<Vec<u32>> {
    let map: HashMap<String, ConstInt> = consts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    compute_dim_signature(&parse_body(body_src), &map)
}

#[test]
fn dim_signature_concatenates_in_source_order() {
    assert_eq!(
        dim_sig("var a[2]; var b[3]; var c[4]; return a;"),
        Some(vec![2, 3, 4])
    );
    // 2D decl contributes both dims in order.
    assert_eq!(
        dim_sig("var m[2][3]; var v[5]; return v;"),
        Some(vec![2, 3, 5])
    );
    // No array decls → empty (but resolvable) signature.
    assert_eq!(dim_sig("return x + 1;"), Some(vec![]));
}

#[test]
fn dim_signature_traversal_is_then_before_else_and_recurses() {
    assert_eq!(
        dim_sig("if (c) { var t[1]; } else { var e[2]; } var tail[3]; return x;"),
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        dim_sig("for (var i = 0; i < n; i++) { var loop_arr[7]; } return x;"),
        Some(vec![7])
    );
}

#[test]
fn dim_signature_folds_against_param_consts() {
    assert_eq!(
        dim_sig_with("var a[n]; var b[m]; return a;", &[("n", 8), ("m", 16)]),
        Some(vec![8, 16])
    );
}

#[test]
fn dim_signature_is_none_on_any_runtime_dim() {
    // `m` does not fold → whole signature is unresolvable.
    assert_eq!(
        dim_sig_with("var a[n]; var b[m]; return a;", &[("n", 8)]),
        None
    );
    assert_eq!(dim_sig("var a[2]; var b[k]; return a;"), None);
}

#[test]
fn reg_type_collapse_is_one_handle_per_array() {
    assert_eq!(
        CalleeReturnShape::Scalar.to_reg_types(),
        Some(vec![RegType::Field])
    );
    assert_eq!(
        CalleeReturnShape::Array(7).to_reg_types(),
        Some(vec![RegType::Array(ElemT::Field)])
    );
    assert_eq!(
        CalleeReturnShape::Array2D(3, 4).to_reg_types(),
        Some(vec![RegType::Array(ElemT::Field)])
    );
    assert_eq!(CalleeReturnShape::Other.to_reg_types(), None);
}
