use achronyme_parser::ast::{BaseType, Expr, Stmt, TypeAnnotation, Visibility};
use achronyme_parser::{parse_program, Severity};

fn parse_ok(source: &str) {
    let (_, errors) = parse_program(source);
    let real_errors: Vec<_> = errors
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(
        real_errors.is_empty(),
        "unexpected parse errors: {real_errors:?}"
    );
}

fn has_errors(source: &str) -> bool {
    let (_, errors) = parse_program(source);
    errors.iter().any(|d| d.severity == Severity::Error)
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
// Phase G: prove(public: [...]) syntax — now emits W010 deprecation
// ===================================================================

#[test]
fn prove_public_list_basic() {
    let input = r#"prove(public: [hash]) { assert_eq(poseidon(secret, 0), hash) }"#;
    parse_ok(input);
    let (prog, errors) = parse_program(input);
    // Should emit W010 deprecation warning
    assert!(errors.iter().any(|d| d.code.as_deref() == Some("W010")));
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "hash");
            assert_eq!(
                params[0].type_ann.as_ref().unwrap().visibility,
                Some(Visibility::Public)
            );
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
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert_eq!(params.len(), 3);
            assert_eq!(params[0].name, "a");
            assert_eq!(params[1].name, "b");
            assert_eq!(params[2].name, "c");
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
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert!(params.is_empty());
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_old_syntax_no_params() {
    let input = r#"prove { witness s; public h; assert_eq(s, h) }"#;
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert!(params.is_empty(), "old syntax should have no params");
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
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "x");
            assert_eq!(params[1].name, "y");
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
                    params,
                    ..
                },
            ..
        } => {
            assert_eq!(name, "vote");
            assert_eq!(prove_name.as_deref(), Some("vote"));
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "root");
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
fn prove_named_no_params() {
    let input = r#"prove vote { witness x; public y; assert_eq(x, y) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::LetDecl {
            name,
            value:
                Expr::Prove {
                    name: prove_name,
                    params,
                    ..
                },
            ..
        } => {
            assert_eq!(name, "vote");
            assert_eq!(prove_name.as_deref(), Some("vote"));
            assert!(params.is_empty());
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

// ===================================================================
// New param-style prove syntax
// ===================================================================

#[test]
fn prove_param_style_basic() {
    let input = r#"prove(hash: Public) { assert_eq(poseidon(secret, 0), hash) }"#;
    parse_ok(input);
    let (prog, errors) = parse_program(input);
    // New syntax should NOT emit W010
    assert!(!errors.iter().any(|d| d.code.as_deref() == Some("W010")));
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "hash");
            let ann = params[0].type_ann.as_ref().unwrap();
            assert_eq!(ann.visibility, Some(Visibility::Public));
            assert_eq!(ann.base, BaseType::Field);
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_param_style_multiple() {
    let input = r#"prove(root: Public, flag: Public Bool) { assert(flag) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { params, .. }) => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "root");
            assert_eq!(params[0].type_ann.as_ref().unwrap().base, BaseType::Field);
            assert_eq!(params[1].name, "flag");
            assert_eq!(params[1].type_ann.as_ref().unwrap().base, BaseType::Bool);
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn prove_param_style_named() {
    let input = r#"prove vote(hash: Public) { assert_eq(hash, hash) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::LetDecl {
            name,
            value:
                Expr::Prove {
                    name: prove_name,
                    params,
                    ..
                },
            ..
        } => {
            assert_eq!(name, "vote");
            assert_eq!(prove_name.as_deref(), Some("vote"));
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "hash");
        }
        other => panic!("expected LetDecl with named Prove, got {other:?}"),
    }
}

// ===================================================================
// Circuit keyword
// ===================================================================

#[test]
fn circuit_decl_parses() {
    // Old syntax — emits W008 deprecation but still parses
    let input =
        r#"circuit hash_check(public output, witness secret) { assert_eq(output, secret) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::CircuitDecl {
            name, params, body, ..
        } => {
            assert_eq!(name, "hash_check");
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "output");
            assert_eq!(
                params[0].type_ann.as_ref().unwrap().visibility,
                Some(Visibility::Public)
            );
            assert_eq!(params[1].name, "secret");
            assert_eq!(
                params[1].type_ann.as_ref().unwrap().visibility,
                Some(Visibility::Witness)
            );
            assert!(!body.stmts.is_empty());
        }
        other => panic!("expected CircuitDecl, got {other:?}"),
    }
}

#[test]
fn circuit_decl_with_array_params() {
    // Old syntax — emits W008 deprecation but still parses
    let input = r#"circuit merkle(public root, witness path[3], witness indices[3]) { assert(root == root) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::CircuitDecl { params, .. } => {
            assert_eq!(params.len(), 3);
            assert!(params[0].type_ann.as_ref().unwrap().array_size.is_none());
            assert_eq!(params[1].type_ann.as_ref().unwrap().array_size, Some(3));
            assert_eq!(params[2].type_ann.as_ref().unwrap().array_size, Some(3));
        }
        other => panic!("expected CircuitDecl, got {other:?}"),
    }
}

#[test]
fn circuit_call_with_keyword_args() {
    let input = r#"hash_check(output: x, secret: y)"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Call { callee, args, .. }) => {
            if let Expr::Ident { name, .. } = callee.as_ref() {
                assert_eq!(name, "hash_check");
            } else {
                panic!("expected Ident callee");
            }
            assert_eq!(args.len(), 2);
            assert_eq!(args[0].name.as_deref(), Some("output"));
            assert_eq!(args[1].name.as_deref(), Some("secret"));
        }
        other => panic!("expected Call with keyword args, got {other:?}"),
    }
}

#[test]
fn import_circuit_parses() {
    let input = r#"import circuit "./hash.ach" as hash_check"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::ImportCircuit { path, alias, .. } => {
            assert_eq!(path, "./hash.ach");
            assert_eq!(alias, "hash_check");
        }
        other => panic!("expected ImportCircuit, got {other:?}"),
    }
}

#[test]
fn regular_call_still_positional() {
    let input = r#"add(1, 2)"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Call { args, .. }) => {
            assert_eq!(args.len(), 2);
        }
        other => panic!("expected regular Call, got {other:?}"),
    }
}

// ===================================================================
// New circuit param syntax
// ===================================================================

#[test]
fn circuit_decl_new_syntax() {
    let input =
        r#"circuit hash_check(output: Public, secret: Witness) { assert_eq(output, secret) }"#;
    parse_ok(input);
    let (prog, errors) = parse_program(input);
    // New syntax should NOT emit W008
    assert!(!errors.iter().any(|d| d.code.as_deref() == Some("W008")));
    match &prog.stmts[0] {
        Stmt::CircuitDecl {
            name, params, body, ..
        } => {
            assert_eq!(name, "hash_check");
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "output");
            assert_eq!(
                params[0].type_ann.as_ref().unwrap().visibility,
                Some(Visibility::Public)
            );
            assert_eq!(params[1].name, "secret");
            assert_eq!(
                params[1].type_ann.as_ref().unwrap().visibility,
                Some(Visibility::Witness)
            );
            assert!(!body.stmts.is_empty());
        }
        other => panic!("expected CircuitDecl, got {other:?}"),
    }
}

#[test]
fn circuit_decl_new_syntax_with_types() {
    let input = r#"circuit merkle(root: Public, path: Witness Field[3]) { assert(root == root) }"#;
    parse_ok(input);
    let (prog, _) = parse_program(input);
    match &prog.stmts[0] {
        Stmt::CircuitDecl { params, .. } => {
            assert_eq!(params.len(), 2);
            let root_ann = params[0].type_ann.as_ref().unwrap();
            assert_eq!(root_ann.visibility, Some(Visibility::Public));
            assert_eq!(root_ann.base, BaseType::Field);
            assert!(root_ann.array_size.is_none());

            let path_ann = params[1].type_ann.as_ref().unwrap();
            assert_eq!(path_ann.visibility, Some(Visibility::Witness));
            assert_eq!(path_ann.base, BaseType::Field);
            assert_eq!(path_ann.array_size, Some(3));
        }
        other => panic!("expected CircuitDecl, got {other:?}"),
    }
}
