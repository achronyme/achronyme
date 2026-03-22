use achronyme_parser::ast::{Expr, Stmt};
use achronyme_parser::parse_program;

fn parse_ok(source: &str) {
    let (_, errors) = parse_program(source);
    assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
}

fn has_errors(source: &str) -> bool {
    let (_, errors) = parse_program(source);
    !errors.is_empty()
}

#[test]
fn prove_expr_parses() {
    let input = r#"prove { witness s; public h; assert_eq(poseidon(s, 0), h) }"#;
    parse_ok(input);
}

#[test]
fn prove_expr_empty_block() {
    let input = "prove { }";
    parse_ok(input);
}

#[test]
fn prove_is_keyword_not_identifier() {
    // "prove" alone should NOT parse as a valid identifier expression
    let input = "let prove = 1";
    assert!(
        has_errors(input),
        "prove should be a keyword, not an identifier"
    );
}

#[test]
fn prove_expr_with_arithmetic() {
    let input = r#"prove {
        witness a, b
        public c
        assert_eq(a + b, c)
    }"#;
    parse_ok(input);
}

#[test]
fn prove_after_let() {
    let input = r#"
        let x = 42
        prove { witness x; assert_eq(x, 42) }
    "#;
    parse_ok(input);
}

// ===================================================================
// Phase G: prove(public: [...]) syntax tests
// ===================================================================

#[test]
fn prove_public_list_basic() {
    let input = r#"prove(public: [hash]) { assert_eq(poseidon(secret, 0), hash) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { public_list, .. }) => {
            let names = public_list.as_ref().expect("should have public_list");
            assert_eq!(names, &["hash"]);
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_public_list_multiple() {
    let input = r#"prove(public: [a, b, c]) { assert_eq(a + b, c) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { public_list, .. }) => {
            let names = public_list.as_ref().expect("should have public_list");
            assert_eq!(names, &["a", "b", "c"]);
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_public_list_empty() {
    let input = r#"prove(public: []) { assert(1 == 1) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { public_list, .. }) => {
            let names = public_list.as_ref().expect("should have public_list");
            assert!(names.is_empty());
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_old_syntax_no_public_list() {
    let input = r#"prove { witness s; public h; assert_eq(s, h) }"#;
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { public_list, .. }) => {
            assert!(
                public_list.is_none(),
                "old syntax should have no public_list"
            );
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_public_list_trailing_comma() {
    let input = r#"prove(public: [x, y,]) { assert_eq(x, y) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { public_list, .. }) => {
            let names = public_list.as_ref().expect("should have public_list");
            assert_eq!(names, &["x", "y"]);
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

// ===================================================================
// Named prove blocks
// ===================================================================

#[test]
fn prove_named_statement() {
    let input = r#"prove vote(public: [root]) { assert_eq(root, root) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::LetDecl {
            name,
            value:
                Expr::Prove {
                    name: prove_name,
                    public_list,
                    ..
                },
            ..
        } => {
            assert_eq!(name, "vote");
            assert_eq!(prove_name.as_deref(), Some("vote"));
            let pubs = public_list.as_ref().expect("should have public_list");
            assert_eq!(pubs, &["root"]);
        }
        other => panic!("expected LetDecl with named Prove, got {other:?}"),
    }
}

#[test]
fn prove_named_expression() {
    let input = r#"let p = prove eligibility(public: [root]) { assert_eq(root, root) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::LetDecl {
            name,
            value: Expr::Prove {
                name: prove_name, ..
            },
            ..
        } => {
            assert_eq!(name, "p");
            assert_eq!(prove_name.as_deref(), Some("eligibility"));
        }
        other => panic!("expected LetDecl with named Prove, got {other:?}"),
    }
}

#[test]
fn prove_named_no_public_list() {
    let input = r#"prove vote { witness x; public y; assert_eq(x, y) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::LetDecl {
            name,
            value:
                Expr::Prove {
                    name: prove_name,
                    public_list,
                    ..
                },
            ..
        } => {
            assert_eq!(name, "vote");
            assert_eq!(prove_name.as_deref(), Some("vote"));
            assert!(public_list.is_none());
        }
        other => panic!("expected LetDecl with named Prove, got {other:?}"),
    }
}

#[test]
fn prove_anonymous_still_works() {
    let input = r#"prove(public: [h]) { assert_eq(h, h) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { name, .. }) => {
            assert!(name.is_none());
        }
        other => panic!("expected anonymous Prove, got {other:?}"),
    }
}
