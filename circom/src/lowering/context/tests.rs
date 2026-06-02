use super::*;
use crate::ast::{AnonSignalArg, BinOp as AstBinOp, Expr};
use diagnostics::Span;

fn span() -> Span {
    Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    }
}

fn ident(name: &str) -> Expr {
    Expr::Ident {
        name: name.to_string(),
        span: span(),
    }
}

fn number(value: &str) -> Expr {
    Expr::Number {
        value: value.to_string(),
        span: span(),
    }
}

fn bin_add(lhs: Expr, rhs: Expr) -> Expr {
    Expr::BinOp {
        op: AstBinOp::Add,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        span: span(),
    }
}

fn index(object: Expr, idx: Expr) -> Expr {
    Expr::Index {
        object: Box::new(object),
        index: Box::new(idx),
        span: span(),
    }
}

fn ternary(cond: Expr, t: Expr, f: Expr) -> Expr {
    Expr::Ternary {
        condition: Box::new(cond),
        if_true: Box::new(t),
        if_false: Box::new(f),
        span: span(),
    }
}

fn call(callee: Expr, args: Vec<Expr>) -> Expr {
    Expr::Call {
        callee: Box::new(callee),
        args,
        span: span(),
    }
}

fn dot(object: Expr, field: &str) -> Expr {
    Expr::DotAccess {
        object: Box::new(object),
        field: field.to_string(),
        span: span(),
    }
}

fn array_lit(elements: Vec<Expr>) -> Expr {
    Expr::ArrayLit {
        elements,
        span: span(),
    }
}

fn tuple(elements: Vec<Expr>) -> Expr {
    Expr::Tuple {
        elements,
        span: span(),
    }
}

fn anon_component(callee: Expr, template_args: Vec<Expr>, signal_args: Vec<Expr>) -> Expr {
    Expr::AnonComponent {
        callee: Box::new(callee),
        template_args,
        signal_args: signal_args
            .into_iter()
            .map(|value| AnonSignalArg { name: None, value })
            .collect(),
        span: span(),
    }
}

fn ctx_with_placeholder(var: &str, token: u32) -> LoweringContext<'_> {
    let mut ctx = LoweringContext::empty();
    ctx.placeholder_loop_var = Some((var.to_string(), token));
    ctx
}

#[test]
fn placeholder_appears_in_returns_false_when_no_placeholder_set() {
    let ctx = LoweringContext::empty();
    let e = ident("i");
    assert!(!ctx.placeholder_appears_in(&e));
}

#[test]
fn placeholder_appears_in_matches_bare_ident() {
    let ctx = ctx_with_placeholder("i", 7);
    assert!(ctx.placeholder_appears_in(&ident("i")));
    assert!(!ctx.placeholder_appears_in(&ident("j")));
}

#[test]
fn placeholder_appears_in_walks_nested_shapes() {
    let ctx = ctx_with_placeholder("i", 0);
    assert!(ctx.placeholder_appears_in(&bin_add(ident("i"), ident("k"))));
    let inner = index(ident("c"), ident("i"));
    let outer = index(inner, ident("k"));
    assert!(ctx.placeholder_appears_in(&outer));
    let no_i = index(index(ident("c"), ident("j")), ident("k"));
    assert!(!ctx.placeholder_appears_in(&no_i));
}

#[test]
fn placeholder_appears_in_walks_call_and_anon_component() {
    let ctx = ctx_with_placeholder("i", 1);
    // Call with placeholder in args
    assert!(ctx.placeholder_appears_in(&call(ident("f"), vec![ident("i")])));
    // Call with placeholder in callee (false positive but benign - see doc)
    assert!(ctx.placeholder_appears_in(&call(ident("i"), vec![number("1")])));
    // Call without placeholder
    assert!(!ctx.placeholder_appears_in(&call(ident("f"), vec![number("1")])));
    // AnonComponent: placeholder in template_args
    assert!(ctx.placeholder_appears_in(&anon_component(
        ident("T"),
        vec![ident("i")],
        vec![number("0")],
    )));
    // AnonComponent: placeholder in signal_args[i].value
    assert!(ctx.placeholder_appears_in(&anon_component(
        ident("T"),
        vec![number("3")],
        vec![ident("i")],
    )));
    // AnonComponent: no placeholder anywhere
    assert!(!ctx.placeholder_appears_in(&anon_component(
        ident("T"),
        vec![number("3")],
        vec![number("0")],
    )));
}

#[test]
fn placeholder_appears_in_walks_ternary_branches_independently() {
    let ctx = ctx_with_placeholder("i", 2);
    // Only condition references i
    assert!(ctx.placeholder_appears_in(&ternary(ident("i"), number("1"), number("0"))));
    // Only if_true references i
    assert!(ctx.placeholder_appears_in(&ternary(ident("c"), ident("i"), number("0"))));
    // Only if_false references i
    assert!(ctx.placeholder_appears_in(&ternary(ident("c"), number("1"), ident("i"))));
    // None reference i
    assert!(!ctx.placeholder_appears_in(&ternary(ident("c"), number("1"), number("0"))));
}

#[test]
fn placeholder_appears_in_walks_dot_access_array_and_tuple() {
    let ctx = ctx_with_placeholder("i", 3);
    // DotAccess: object recurses
    assert!(ctx.placeholder_appears_in(&dot(ident("i"), "out")));
    assert!(!ctx.placeholder_appears_in(&dot(ident("comp"), "i")));
    // ArrayLit recurses
    assert!(ctx.placeholder_appears_in(&array_lit(vec![number("0"), ident("i")])));
    assert!(!ctx.placeholder_appears_in(&array_lit(vec![number("0"), number("1")])));
    // Tuple recurses
    assert!(ctx.placeholder_appears_in(&tuple(vec![number("0"), ident("i")])));
    assert!(!ctx.placeholder_appears_in(&tuple(vec![number("0"), number("1")])));
}

#[test]
fn placeholder_appears_in_returns_false_for_terminal_variants() {
    let ctx = ctx_with_placeholder("i", 4);
    assert!(!ctx.placeholder_appears_in(&number("42")));
    assert!(!ctx.placeholder_appears_in(&Expr::HexNumber {
        value: "0xff".to_string(),
        span: span(),
    }));
    assert!(!ctx.placeholder_appears_in(&Expr::Underscore { span: span() }));
    assert!(!ctx.placeholder_appears_in(&Expr::Error { span: span() }));
}
