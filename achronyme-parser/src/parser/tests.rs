use super::*;

/// Parse source and return the AST, panicking on any parse error.
fn parse_ok(source: &str) -> Program {
    let (prog, errors) = parse_program(source);
    assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
    prog
}

/// Parse source expecting errors, returning true if any errors were produced.
fn has_errors(source: &str) -> bool {
    let (_, errors) = parse_program(source);
    !errors.is_empty()
}

#[test]
fn parse_simple_number() {
    let prog = parse_ok("42");
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Number { value, .. }) => assert_eq!(value, "42"),
        other => panic!("expected Number, got {other:?}"),
    }
}

#[test]
fn parse_negative_number() {
    let prog = parse_ok("-7");
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp { op, operand, .. }) => {
            assert_eq!(*op, UnaryOp::Neg);
            match operand.as_ref() {
                Expr::Number { value, .. } => assert_eq!(value, "7"),
                other => panic!("expected Number, got {other:?}"),
            }
        }
        other => panic!("expected UnaryOp(Neg), got {other:?}"),
    }
}

#[test]
fn parse_let_decl() {
    let prog = parse_ok("let x = 5");
    match &prog.stmts[0] {
        Stmt::LetDecl { name, value, .. } => {
            assert_eq!(name, "x");
            match value {
                Expr::Number { value: v, .. } => assert_eq!(v, "5"),
                other => panic!("expected Number, got {other:?}"),
            }
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_binary_add() {
    let prog = parse_ok("a + b");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp { op, lhs, rhs, .. }) => {
            assert_eq!(*op, BinOp::Add);
            match lhs.as_ref() {
                Expr::Ident { name, .. } => assert_eq!(name, "a"),
                other => panic!("expected Ident, got {other:?}"),
            }
            match rhs.as_ref() {
                Expr::Ident { name, .. } => assert_eq!(name, "b"),
                other => panic!("expected Ident, got {other:?}"),
            }
        }
        other => panic!("expected BinOp, got {other:?}"),
    }
}

#[test]
fn parse_function_call() {
    let prog = parse_ok("foo(1, 2)");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Call { callee, args, .. }) => {
            match callee.as_ref() {
                Expr::Ident { name, .. } => assert_eq!(name, "foo"),
                other => panic!("expected Ident, got {other:?}"),
            }
            assert_eq!(args.len(), 2);
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn parse_array_literal() {
    let prog = parse_ok("let arr = [1, 2, 3]");
    match &prog.stmts[0] {
        Stmt::LetDecl { value, .. } => match value {
            Expr::Array { elements, .. } => assert_eq!(elements.len(), 3),
            other => panic!("expected Array, got {other:?}"),
        },
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_if_else() {
    let prog = parse_ok("if x { 1 } else { 2 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::If { else_branch, .. }) => {
            assert!(else_branch.is_some());
        }
        other => panic!("expected If, got {other:?}"),
    }
}

#[test]
fn parse_for_range() {
    let prog = parse_ok("for i in 0..5 { i }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::For { var, iterable, .. }) => {
            assert_eq!(var, "i");
            match iterable {
                ForIterable::Range { start, end } => {
                    assert_eq!(*start, 0);
                    assert_eq!(*end, 5);
                }
                other => panic!("expected Range, got {other:?}"),
            }
        }
        other => panic!("expected For, got {other:?}"),
    }
}

#[test]
fn parse_fn_decl() {
    let prog = parse_ok("fn add(a, b) { a + b }");
    match &prog.stmts[0] {
        Stmt::FnDecl {
            name,
            params,
            return_type,
            ..
        } => {
            assert_eq!(name, "add");
            let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, &["a", "b"]);
            assert!(params.iter().all(|p| p.type_ann.is_none()));
            assert!(return_type.is_none());
        }
        other => panic!("expected FnDecl, got {other:?}"),
    }
}

#[test]
fn parse_public_witness_decl() {
    let prog = parse_ok("public x, y\nwitness z[3]");
    assert_eq!(prog.stmts.len(), 2);
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert_eq!(names.len(), 2);
            assert_eq!(names[0].name, "x");
            assert!(names[0].array_size.is_none());
            assert_eq!(names[1].name, "y");
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
    match &prog.stmts[1] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names.len(), 1);
            assert_eq!(names[0].name, "z");
            assert_eq!(names[0].array_size, Some(3));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_prove_block() {
    let prog = parse_ok("prove { 1 + 2 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { params, body, .. }) => {
            assert!(params.is_empty(), "old syntax should have no params");
            assert!(!body.stmts.is_empty(), "body should have statements");
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn reject_chained_comparisons() {
    // P-03: comparison operators cannot be chained
    assert!(has_errors("a < b < c"));
    assert!(has_errors("a == b == c"));
    assert!(has_errors("a >= b <= c"));
    // Single comparison is fine
    assert!(!has_errors("a < b"));
    // Combining with && is fine
    assert!(!has_errors("a < b && b < c"));
}

#[test]
fn parse_unary_ops() {
    let prog = parse_ok("-x");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp { op, .. }) => assert_eq!(*op, UnaryOp::Neg),
        other => panic!("expected UnaryOp, got {other:?}"),
    }
}

#[test]
fn parse_index_access() {
    let prog = parse_ok("arr[0]");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Index { .. }) => {}
        other => panic!("expected Index, got {other:?}"),
    }
}

#[test]
fn parse_dot_access() {
    let prog = parse_ok("obj.field");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::DotAccess { field, .. }) => assert_eq!(field, "field"),
        other => panic!("expected DotAccess, got {other:?}"),
    }
}

#[test]
fn parse_map_literal() {
    let prog = parse_ok(r#"{ key: 1, "str_key": 2 }"#);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Map { pairs, .. }) => {
            assert_eq!(pairs.len(), 2);
        }
        other => panic!("expected Map, got {other:?}"),
    }
}

#[test]
fn parse_block_source() {
    let block = parse_block("{ let x = 1; x + 2 }").unwrap();
    assert_eq!(block.stmts.len(), 2);
}

#[test]
fn parse_precedence() {
    // a + b * c should parse as a + (b * c)
    let prog = parse_ok("a + b * c");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp {
            op: BinOp::Add,
            rhs,
            ..
        }) => match rhs.as_ref() {
            Expr::BinOp { op: BinOp::Mul, .. } => {}
            other => panic!("expected Mul on rhs, got {other:?}"),
        },
        other => panic!("expected Add, got {other:?}"),
    }
}

#[test]
fn parse_chained_comparison() {
    let prog = parse_ok("a == b");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp { op: BinOp::Eq, .. }) => {}
        other => panic!("expected Eq, got {other:?}"),
    }
}

#[test]
fn parse_logical_operators() {
    let prog = parse_ok("a && b || c");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp {
            op: BinOp::Or, lhs, ..
        }) => match lhs.as_ref() {
            Expr::BinOp { op: BinOp::And, .. } => {}
            other => panic!("expected And on lhs, got {other:?}"),
        },
        other => panic!("expected Or, got {other:?}"),
    }
}

#[test]
fn parse_right_assoc_pow() {
    // 2^3^4 should parse as 2^(3^4)
    let prog = parse_ok("2^3^4");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp {
            op: BinOp::Pow,
            lhs,
            rhs,
            ..
        }) => {
            match lhs.as_ref() {
                Expr::Number { value, .. } => assert_eq!(value, "2"),
                other => panic!("expected Number(2), got {other:?}"),
            }
            match rhs.as_ref() {
                Expr::BinOp { op: BinOp::Pow, .. } => {}
                other => panic!("expected Pow on rhs, got {other:?}"),
            }
        }
        other => panic!("expected Pow, got {other:?}"),
    }
}

#[test]
fn parse_neg_before_pow() {
    // -a^2 should parse as -(a^2)
    let prog = parse_ok("-a^2");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        }) => match operand.as_ref() {
            Expr::BinOp { op: BinOp::Pow, .. } => {}
            other => panic!("expected Pow inside Neg, got {other:?}"),
        },
        other => panic!("expected UnaryOp(Neg), got {other:?}"),
    }
}

#[test]
fn parse_assignment() {
    let prog = parse_ok("x = 5");
    match &prog.stmts[0] {
        Stmt::Assignment { target, value, .. } => {
            match target {
                Expr::Ident { name, .. } => assert_eq!(name, "x"),
                other => panic!("expected Ident target, got {other:?}"),
            }
            match value {
                Expr::Number { value: v, .. } => assert_eq!(v, "5"),
                other => panic!("expected Number, got {other:?}"),
            }
        }
        other => panic!("expected Assignment, got {other:?}"),
    }
}

#[test]
fn parse_empty_program() {
    let prog = parse_ok("");
    assert!(prog.stmts.is_empty());
}

#[test]
fn parse_error_unexpected() {
    let (_, errors) = parse_program(")");
    assert!(!errors.is_empty());
    assert!(errors[0].message.contains("expected expression"));
}

#[test]
fn parse_while_loop() {
    let prog = parse_ok("while x { 1 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::While { .. }) => {}
        other => panic!("expected While, got {other:?}"),
    }
}

#[test]
fn parse_forever_loop() {
    let prog = parse_ok("forever { 1 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Forever { .. }) => {}
        other => panic!("expected Forever, got {other:?}"),
    }
}

#[test]
fn parse_fn_expr_anonymous() {
    let prog = parse_ok("fn(x) { x + 1 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::FnExpr { name, params, .. }) => {
            assert!(name.is_none());
            let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, &["x"]);
        }
        other => panic!("expected FnExpr, got {other:?}"),
    }
}

#[test]
fn parse_for_in_expr() {
    let prog = parse_ok("for x in arr { x }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::For { var, iterable, .. }) => {
            assert_eq!(var, "x");
            match iterable {
                ForIterable::Expr(e) => match e.as_ref() {
                    Expr::Ident { name, .. } => assert_eq!(name, "arr"),
                    other => panic!("expected Ident, got {other:?}"),
                },
                other => panic!("expected Expr iterable, got {other:?}"),
            }
        }
        other => panic!("expected For, got {other:?}"),
    }
}

#[test]
fn parse_else_if() {
    let prog = parse_ok("if a { 1 } else if b { 2 } else { 3 }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::If {
            else_branch: Some(ElseBranch::If(inner)),
            ..
        }) => match inner.as_ref() {
            Expr::If {
                else_branch: Some(ElseBranch::Block(_)),
                ..
            } => {}
            other => panic!("expected inner If with else block, got {other:?}"),
        },
        other => panic!("expected If with else-if, got {other:?}"),
    }
}

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

#[test]
fn parse_let_with_type() {
    let prog = parse_ok("let x: Field = 5");
    match &prog.stmts[0] {
        Stmt::LetDecl { name, type_ann, .. } => {
            assert_eq!(name, "x");
            assert_eq!(*type_ann, Some(TypeAnnotation::field()));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_let_with_bool_type() {
    let prog = parse_ok("let ok: Bool = true");
    match &prog.stmts[0] {
        Stmt::LetDecl { name, type_ann, .. } => {
            assert_eq!(name, "ok");
            assert_eq!(*type_ann, Some(TypeAnnotation::bool()));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_let_without_type() {
    let prog = parse_ok("let x = 5");
    match &prog.stmts[0] {
        Stmt::LetDecl { type_ann, .. } => {
            assert!(type_ann.is_none());
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_mut_with_type() {
    let prog = parse_ok("mut x: Field = 10");
    match &prog.stmts[0] {
        Stmt::MutDecl { name, type_ann, .. } => {
            assert_eq!(name, "x");
            assert_eq!(*type_ann, Some(TypeAnnotation::field()));
        }
        other => panic!("expected MutDecl, got {other:?}"),
    }
}

#[test]
fn parse_public_with_type() {
    let prog = parse_ok("public x: Field");
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert_eq!(names[0].name, "x");
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::field()));
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn parse_witness_with_type() {
    let prog = parse_ok("witness flag: Bool");
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].name, "flag");
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::bool()));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_witness_array_with_type() {
    let prog = parse_ok("witness path[3]: Field");
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].name, "path");
            assert_eq!(names[0].array_size, Some(3));
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::field()));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_public_without_type() {
    let prog = parse_ok("public x");
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert!(names[0].type_ann.is_none());
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_with_typed_params() {
    let prog = parse_ok("fn hash(a: Field, b: Field) -> Field { a + b }");
    match &prog.stmts[0] {
        Stmt::FnDecl {
            name,
            params,
            return_type,
            ..
        } => {
            assert_eq!(name, "hash");
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "a");
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::field()));
            assert_eq!(params[1].name, "b");
            assert_eq!(params[1].type_ann, Some(TypeAnnotation::field()));
            assert_eq!(*return_type, Some(TypeAnnotation::field()));
        }
        other => panic!("expected FnDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_mixed_typed_untyped_params() {
    let prog = parse_ok("fn f(a: Field, b) { a + b }");
    match &prog.stmts[0] {
        Stmt::FnDecl {
            params,
            return_type,
            ..
        } => {
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::field()));
            assert!(params[1].type_ann.is_none());
            assert!(return_type.is_none());
        }
        other => panic!("expected FnDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_expr_with_return_type() {
    let prog = parse_ok("fn(x: Bool) -> Bool { !x }");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::FnExpr {
            params,
            return_type,
            ..
        }) => {
            assert_eq!(params[0].name, "x");
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::bool()));
            assert_eq!(*return_type, Some(TypeAnnotation::bool()));
        }
        other => panic!("expected FnExpr, got {other:?}"),
    }
}

#[test]
fn parse_arrow_token() {
    // Ensure -> doesn't interfere with subtraction
    let prog = parse_ok("a - b");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp { op: BinOp::Sub, .. }) => {}
        other => panic!("expected Sub, got {other:?}"),
    }
}

#[test]
fn parse_negative_still_works() {
    // Ensure negation still works after lexer change
    let prog = parse_ok("-5");
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp {
            op: UnaryOp::Neg, ..
        }) => {}
        other => panic!("expected Neg, got {other:?}"),
    }
}

#[test]
fn parse_type_annotation_array() {
    let prog = parse_ok("let a: Field[4] = [1, 2, 3, 4]");
    match &prog.stmts[0] {
        Stmt::LetDecl { type_ann, .. } => {
            assert_eq!(*type_ann, Some(TypeAnnotation::field_array(4)));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_type_annotation_bool_array() {
    let prog = parse_ok("witness flags[2]: Bool[2]");
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::bool_array(2)));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_invalid_type_annotation() {
    assert!(has_errors("let x: Integer = 5"));
}

#[test]
fn parse_multiple_public_with_types() {
    let prog = parse_ok("public x: Field, y: Bool");
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert_eq!(names.len(), 2);
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::field()));
            assert_eq!(names[1].type_ann, Some(TypeAnnotation::bool()));
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn field_and_bool_not_keywords() {
    // Field and Bool are NOT keywords, they can be used as identifiers
    let prog = parse_ok("let Field = 5");
    match &prog.stmts[0] {
        Stmt::LetDecl { name, .. } => assert_eq!(name, "Field"),
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

// ====================================================================
// Import / Export tests
// ====================================================================

#[test]
fn parse_import_basic() {
    let prog = parse_ok(r#"import "./utils.ach" as utils"#);
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Import { path, alias, .. } => {
            assert_eq!(path, "./utils.ach");
            assert_eq!(alias, "utils");
        }
        other => panic!("expected Import, got {other:?}"),
    }
}

#[test]
fn parse_export_fn() {
    let prog = parse_ok("export fn add(a, b) { a + b }");
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Export { inner, .. } => match inner.as_ref() {
            Stmt::FnDecl { name, params, .. } => {
                assert_eq!(name, "add");
                assert_eq!(params.len(), 2);
            }
            other => panic!("expected FnDecl inside Export, got {other:?}"),
        },
        other => panic!("expected Export, got {other:?}"),
    }
}

#[test]
fn parse_export_let() {
    let prog = parse_ok("export let PI = 3");
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Export { inner, .. } => match inner.as_ref() {
            Stmt::LetDecl { name, .. } => assert_eq!(name, "PI"),
            other => panic!("expected LetDecl inside Export, got {other:?}"),
        },
        other => panic!("expected Export, got {other:?}"),
    }
}

#[test]
fn parse_export_mut_error() {
    // export mut should fail
    assert!(has_errors("export mut x = 5"));
}

#[test]
fn parse_import_no_as_error() {
    // import without "as" should fail
    assert!(has_errors(r#"import "./foo.ach""#));
}

#[test]
fn import_export_as_are_keywords() {
    // import, export, and as are now keywords and cannot be used as variable names
    assert!(has_errors("let import = 5"));
    assert!(has_errors("let export = 5"));
    assert!(has_errors("let as = 5"));
}

// ====================================================================
// Error recovery tests (issue #63)
// ====================================================================

#[test]
fn recovery_collects_multiple_errors() {
    let source = "let x = \nlet y = 2\nlet z = ";
    let (prog, errors) = parse_program(source);
    // Should collect 2 errors (lines 1 and 3) and still parse line 2
    assert_eq!(errors.len(), 2);
    // AST should have 3 statements (Error, LetDecl, Error)
    assert_eq!(prog.stmts.len(), 3);
    assert!(matches!(&prog.stmts[0], Stmt::Error { .. }));
    assert!(matches!(&prog.stmts[1], Stmt::LetDecl { .. }));
    assert!(matches!(&prog.stmts[2], Stmt::Error { .. }));
}

#[test]
fn recovery_at_semicolons() {
    let source = "let a = ; let b = 2; let c = ;";
    let (prog, errors) = parse_program(source);
    assert_eq!(errors.len(), 2);
    // a errors, b succeeds, c errors
    assert!(matches!(&prog.stmts[1], Stmt::LetDecl { name, .. } if name == "b"));
}

#[test]
fn recovery_at_declaration_keywords() {
    // `)` fails; `let x = 1` ok; `let = 5` fails (missing ident); `fn add` ok
    let source = ")\nlet x = 1\nlet = 5\nfn add(a, b) { a + b }";
    let (prog, errors) = parse_program(source);
    assert!(errors.len() >= 2);
    let good_stmts: Vec<_> = prog
        .stmts
        .iter()
        .filter(|s| !matches!(s, Stmt::Error { .. }))
        .collect();
    assert_eq!(good_stmts.len(), 2);
    assert!(matches!(good_stmts[0], Stmt::LetDecl { name, .. } if name == "x"));
    assert!(matches!(good_stmts[1], Stmt::FnDecl { name, .. } if name == "add"));
}

#[test]
fn recovery_valid_program_no_errors() {
    let source = "let x = 1\nlet y = 2\nlet z = x + y";
    let (prog, errors) = parse_program(source);
    assert!(errors.is_empty());
    assert_eq!(prog.stmts.len(), 3);
    assert!(prog.stmts.iter().all(|s| !matches!(s, Stmt::Error { .. })));
}

#[test]
fn recovery_error_limit() {
    // Generate 25 errors — should stop at 20
    let source = (0..25).map(|_| "let = ;").collect::<Vec<_>>().join("\n");
    let (_prog, errors) = parse_program(&source);
    assert_eq!(errors.len(), 20);
}

#[test]
fn recovery_single_error_still_works() {
    let source = ")";
    let (prog, errors) = parse_program(source);
    assert_eq!(errors.len(), 1);
    assert_eq!(prog.stmts.len(), 1);
    assert!(matches!(&prog.stmts[0], Stmt::Error { .. }));
}

#[test]
fn recovery_empty_source_no_errors() {
    let (prog, errors) = parse_program("");
    assert!(errors.is_empty());
    assert!(prog.stmts.is_empty());
}

#[test]
fn recovery_interleaved_good_and_bad() {
    // `let = ` fails (missing ident); valid lets succeed
    let source = "let a = 1\nlet = 5\nlet b = 2\nlet = 5\nlet c = 3";
    let (prog, errors) = parse_program(source);
    assert_eq!(errors.len(), 2);
    let good: Vec<_> = prog
        .stmts
        .iter()
        .filter(|s| matches!(s, Stmt::LetDecl { .. }))
        .collect();
    assert_eq!(good.len(), 3);
}

// ==========================================================================
// ExprId allocation — Movimiento 2 Phase 3A
// ==========================================================================

/// Walk every `Expr` reachable from a `Program` and invoke `visit` for each.
/// Includes sub-expressions recursively so we can validate id uniqueness
/// across the whole AST.
fn walk_exprs(prog: &Program, mut visit: impl FnMut(&Expr)) {
    fn walk_stmt(stmt: &Stmt, visit: &mut dyn FnMut(&Expr)) {
        match stmt {
            Stmt::LetDecl { value, .. }
            | Stmt::MutDecl { value, .. }
            | Stmt::Expr(value)
            | Stmt::Print { value, .. } => walk_expr(value, visit),
            Stmt::Assignment { target, value, .. } => {
                walk_expr(target, visit);
                walk_expr(value, visit);
            }
            Stmt::Return { value, .. } => {
                if let Some(v) = value {
                    walk_expr(v, visit);
                }
            }
            Stmt::FnDecl { body, .. } | Stmt::CircuitDecl { body, .. } => walk_block(body, visit),
            Stmt::Export { inner, .. } => walk_stmt(inner, visit),
            Stmt::PublicDecl { .. }
            | Stmt::WitnessDecl { .. }
            | Stmt::Break { .. }
            | Stmt::Continue { .. }
            | Stmt::Import { .. }
            | Stmt::SelectiveImport { .. }
            | Stmt::ExportList { .. }
            | Stmt::ImportCircuit { .. }
            | Stmt::Error { .. } => {}
        }
    }

    fn walk_block(block: &Block, visit: &mut dyn FnMut(&Expr)) {
        for s in &block.stmts {
            walk_stmt(s, visit);
        }
    }

    fn walk_expr(expr: &Expr, visit: &mut dyn FnMut(&Expr)) {
        visit(expr);
        match expr {
            Expr::Number { .. }
            | Expr::FieldLit { .. }
            | Expr::BigIntLit { .. }
            | Expr::Bool { .. }
            | Expr::StringLit { .. }
            | Expr::Nil { .. }
            | Expr::Ident { .. }
            | Expr::StaticAccess { .. }
            | Expr::Error { .. } => {}
            Expr::BinOp { lhs, rhs, .. } => {
                walk_expr(lhs, visit);
                walk_expr(rhs, visit);
            }
            Expr::UnaryOp { operand, .. } => walk_expr(operand, visit),
            Expr::Call { callee, args, .. } => {
                walk_expr(callee, visit);
                for a in args {
                    walk_expr(&a.value, visit);
                }
            }
            Expr::Index { object, index, .. } => {
                walk_expr(object, visit);
                walk_expr(index, visit);
            }
            Expr::DotAccess { object, .. } => walk_expr(object, visit),
            Expr::If {
                condition,
                then_block,
                else_branch,
                ..
            } => {
                walk_expr(condition, visit);
                walk_block(then_block, visit);
                match else_branch {
                    Some(ElseBranch::Block(b)) => walk_block(b, visit),
                    Some(ElseBranch::If(e)) => walk_expr(e, visit),
                    None => {}
                }
            }
            Expr::For { body, iterable, .. } => {
                if let ForIterable::Expr(e) | ForIterable::ExprRange { end: e, .. } = iterable {
                    walk_expr(e, visit);
                }
                walk_block(body, visit);
            }
            Expr::While {
                condition, body, ..
            } => {
                walk_expr(condition, visit);
                walk_block(body, visit);
            }
            Expr::Forever { body, .. } => walk_block(body, visit),
            Expr::Block { block, .. } => walk_block(block, visit),
            Expr::FnExpr { body, .. } | Expr::Prove { body, .. } => walk_block(body, visit),
            Expr::Array { elements, .. } => {
                for e in elements {
                    walk_expr(e, visit);
                }
            }
            Expr::Map { pairs, .. } => {
                for (_, v) in pairs {
                    walk_expr(v, visit);
                }
            }
        }
    }

    for s in &prog.stmts {
        walk_stmt(s, &mut visit);
    }
}

#[test]
fn expr_id_synthetic_is_reserved_zero() {
    assert_eq!(ExprId::SYNTHETIC.as_u32(), 0);
    assert!(ExprId::SYNTHETIC.is_synthetic());
    assert!(!ExprId::from_raw(1).is_synthetic());
}

#[test]
fn expr_ids_are_unique_across_program() {
    let source = r#"
        let x = 1 + 2 * 3
        let y = [x, x + 1, foo(x, 2)]
        fn add(a, b) { a + b }
        let z = if x > 0 { add(x, y[0]) } else { -x }
    "#;
    let prog = parse_ok(source);
    let mut seen = std::collections::HashSet::new();
    walk_exprs(&prog, |e| {
        let id = e.id();
        assert!(
            !id.is_synthetic(),
            "parser must never allocate SYNTHETIC (0) to a real expression"
        );
        assert!(
            seen.insert(id),
            "duplicate ExprId {id:?} on expression {e:?}"
        );
    });
    assert!(!seen.is_empty(), "program produced no expressions");
}

#[test]
fn expr_ids_start_at_one_and_are_dense() {
    // A single literal produces one Expr and one id. That id should be 1
    // (the first allocation after SYNTHETIC(0)).
    let prog = parse_ok("42");
    let mut ids = Vec::new();
    walk_exprs(&prog, |e| ids.push(e.id().as_u32()));
    assert_eq!(ids, vec![1]);
}

#[test]
fn expr_ids_are_monotonically_allocated() {
    // Each subsequent parse_program starts fresh (ids reset per Parser),
    // but within one parse they are strictly increasing in allocation
    // order. The parse_program API doesn't let us inspect allocation
    // order directly, so we assert that ids within one program are
    // pairwise distinct and bounded by the total expression count.
    let prog = parse_ok("a + b * c - d");
    let mut count = 0usize;
    let mut max_id = 0u32;
    walk_exprs(&prog, |e| {
        count += 1;
        max_id = max_id.max(e.id().as_u32());
    });
    assert_eq!(count, 7, "expected 4 idents + 3 binops, got {count}");
    // Dense means max id equals count (since first id is 1).
    assert_eq!(max_id as usize, count);
}

#[test]
fn expr_id_accessor_matches_variant_field() {
    // Sanity-check that `Expr::id()` returns the same value as the
    // `id` field on every variant we construct.
    let prog = parse_ok("let x = foo.bar[0]");
    match &prog.stmts[0] {
        Stmt::LetDecl {
            value: Expr::Index { id, object, .. },
            ..
        } => {
            assert_ne!(id.as_u32(), 0);
            assert_eq!(prog.stmts[0].clone().let_value().id(), *id);
            match object.as_ref() {
                Expr::DotAccess { id: dot_id, .. } => assert_ne!(dot_id.as_u32(), 0),
                other => panic!("expected DotAccess inside Index, got {other:?}"),
            }
        }
        other => panic!("expected LetDecl wrapping Index, got {other:?}"),
    }
}

/// Helper for the accessor test — extract the value out of a let decl.
impl Stmt {
    #[cfg(test)]
    fn let_value(self) -> Expr {
        match self {
            Stmt::LetDecl { value, .. } => value,
            _ => panic!("not a LetDecl"),
        }
    }
}
