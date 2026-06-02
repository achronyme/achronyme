use super::*;

#[test]
fn parse_mut_decl() {
    let prog = parse_ok("mut x = 10");
    match &prog.stmts[0] {
        Stmt::MutDecl { name, .. } => assert_eq!(name, "x"),
        other => panic!("expected MutDecl, got {other:?}"),
    }
}

#[test]
fn parse_return_with_value() {
    let prog = parse_ok("return 42");
    match &prog.stmts[0] {
        Stmt::Return {
            value: Some(Expr::Number { value, .. }),
            ..
        } => {
            assert_eq!(value, "42");
        }
        other => panic!("expected Return with value, got {other:?}"),
    }
}

#[test]
fn parse_return_without_value() {
    // `return` followed by `}` has no value
    let prog = parse_ok("if true { return }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::If { then_block, .. }) => match &then_block.stmts[0] {
            Stmt::Return { value: None, .. } => {}
            other => panic!("expected Return without value, got {other:?}"),
        },
        other => panic!("expected If, got {other:?}"),
    }
}

#[test]
fn parse_nil() {
    let prog = parse_ok("nil");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Nil { .. }) => {}
        other => panic!("expected Nil, got {other:?}"),
    }
}

#[test]
fn parse_bool_true() {
    let prog = parse_ok("true");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Bool { value: true, .. }) => {}
        other => panic!("expected Bool(true), got {other:?}"),
    }
}

#[test]
fn parse_string() {
    let prog = parse_ok(r#""hello""#);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::StringLit { value, .. }) => assert_eq!(value, "hello"),
        other => panic!("expected StringLit, got {other:?}"),
    }
}

#[test]
fn parse_not_operator() {
    let prog = parse_ok("!x");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp {
            op: UnaryOp::Not, ..
        }) => {}
        other => panic!("expected Not, got {other:?}"),
    }
}

#[test]
fn parse_semicolons() {
    let prog = parse_ok("1; 2; 3");
    assert_eq!(prog.stmts.len(), 3);
}

#[test]
fn parse_nested_call() {
    let prog = parse_ok("f(g(x))");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Call { callee, args, .. }) => {
            match callee.as_ref() {
                Expr::Ident { name, .. } => assert_eq!(name, "f"),
                other => panic!("expected Ident, got {other:?}"),
            }
            assert_eq!(args.len(), 1);
            match &args[0].value {
                Expr::Call { .. } => {}
                other => panic!("expected inner Call, got {other:?}"),
            }
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

// ========================================================================
// Type annotation tests
// ========================================================================
