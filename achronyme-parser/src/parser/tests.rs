use super::*;

#[test]
fn parse_simple_number() {
    let prog = parse_program("42").unwrap();
    assert_eq!(prog.stmts.len(), 1);
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Number { value, .. }) => assert_eq!(value, "42"),
        other => panic!("expected Number, got {other:?}"),
    }
}

#[test]
fn parse_negative_number() {
    let prog = parse_program("-7").unwrap();
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
    let prog = parse_program("let x = 5").unwrap();
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
    let prog = parse_program("a + b").unwrap();
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
    let prog = parse_program("foo(1, 2)").unwrap();
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
    let prog = parse_program("let arr = [1, 2, 3]").unwrap();
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
    let prog = parse_program("if x { 1 } else { 2 }").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::If { else_branch, .. }) => {
            assert!(else_branch.is_some());
        }
        other => panic!("expected If, got {other:?}"),
    }
}

#[test]
fn parse_for_range() {
    let prog = parse_program("for i in 0..5 { i }").unwrap();
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
    let prog = parse_program("fn add(a, b) { a + b }").unwrap();
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
    let prog = parse_program("public x, y\nwitness z[3]").unwrap();
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
    let prog = parse_program("prove { 1 + 2 }").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Prove { source, .. }) => {
            assert!(source.contains("1 + 2"));
        }
        other => panic!("expected Prove, got {other:?}"),
    }
}

#[test]
fn reject_chained_comparisons() {
    // P-03: comparison operators cannot be chained
    assert!(parse_program("a < b < c").is_err());
    assert!(parse_program("a == b == c").is_err());
    assert!(parse_program("a >= b <= c").is_err());
    // Single comparison is fine
    assert!(parse_program("a < b").is_ok());
    // Combining with && is fine
    assert!(parse_program("a < b && b < c").is_ok());
}

#[test]
fn parse_unary_ops() {
    let prog = parse_program("-x").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp { op, .. }) => assert_eq!(*op, UnaryOp::Neg),
        other => panic!("expected UnaryOp, got {other:?}"),
    }
}

#[test]
fn parse_index_access() {
    let prog = parse_program("arr[0]").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Index { .. }) => {}
        other => panic!("expected Index, got {other:?}"),
    }
}

#[test]
fn parse_dot_access() {
    let prog = parse_program("obj.field").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::DotAccess { field, .. }) => assert_eq!(field, "field"),
        other => panic!("expected DotAccess, got {other:?}"),
    }
}

#[test]
fn parse_map_literal() {
    let prog = parse_program(r#"{ key: 1, "str_key": 2 }"#).unwrap();
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
    let prog = parse_program("a + b * c").unwrap();
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
    let prog = parse_program("a == b").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp { op: BinOp::Eq, .. }) => {}
        other => panic!("expected Eq, got {other:?}"),
    }
}

#[test]
fn parse_logical_operators() {
    let prog = parse_program("a && b || c").unwrap();
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
    let prog = parse_program("2^3^4").unwrap();
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
    let prog = parse_program("-a^2").unwrap();
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
    let prog = parse_program("x = 5").unwrap();
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
    let prog = parse_program("").unwrap();
    assert!(prog.stmts.is_empty());
}

#[test]
fn parse_error_unexpected() {
    let err = parse_program(")").unwrap_err();
    assert!(err.contains("expected expression"));
}

#[test]
fn parse_while_loop() {
    let prog = parse_program("while x { 1 }").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::While { .. }) => {}
        other => panic!("expected While, got {other:?}"),
    }
}

#[test]
fn parse_forever_loop() {
    let prog = parse_program("forever { 1 }").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Forever { .. }) => {}
        other => panic!("expected Forever, got {other:?}"),
    }
}

#[test]
fn parse_fn_expr_anonymous() {
    let prog = parse_program("fn(x) { x + 1 }").unwrap();
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
    let prog = parse_program("for x in arr { x }").unwrap();
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
    let prog = parse_program("if a { 1 } else if b { 2 } else { 3 }").unwrap();
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
    let prog = parse_program("mut x = 10").unwrap();
    match &prog.stmts[0] {
        Stmt::MutDecl { name, .. } => assert_eq!(name, "x"),
        other => panic!("expected MutDecl, got {other:?}"),
    }
}

#[test]
fn parse_return_with_value() {
    let prog = parse_program("return 42").unwrap();
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
    let prog = parse_program("if true { return }").unwrap();
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
    let prog = parse_program("nil").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Nil { .. }) => {}
        other => panic!("expected Nil, got {other:?}"),
    }
}

#[test]
fn parse_bool_true() {
    let prog = parse_program("true").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Bool { value: true, .. }) => {}
        other => panic!("expected Bool(true), got {other:?}"),
    }
}

#[test]
fn parse_string() {
    let prog = parse_program(r#""hello""#).unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::StringLit { value, .. }) => assert_eq!(value, "hello"),
        other => panic!("expected StringLit, got {other:?}"),
    }
}

#[test]
fn parse_not_operator() {
    let prog = parse_program("!x").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp {
            op: UnaryOp::Not, ..
        }) => {}
        other => panic!("expected Not, got {other:?}"),
    }
}

#[test]
fn parse_semicolons() {
    let prog = parse_program("1; 2; 3").unwrap();
    assert_eq!(prog.stmts.len(), 3);
}

#[test]
fn parse_nested_call() {
    let prog = parse_program("f(g(x))").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::Call { callee, args, .. }) => {
            match callee.as_ref() {
                Expr::Ident { name, .. } => assert_eq!(name, "f"),
                other => panic!("expected Ident, got {other:?}"),
            }
            assert_eq!(args.len(), 1);
            match &args[0] {
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
    let prog = parse_program("let x: Field = 5").unwrap();
    match &prog.stmts[0] {
        Stmt::LetDecl { name, type_ann, .. } => {
            assert_eq!(name, "x");
            assert_eq!(*type_ann, Some(TypeAnnotation::Field));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_let_with_bool_type() {
    let prog = parse_program("let ok: Bool = true").unwrap();
    match &prog.stmts[0] {
        Stmt::LetDecl { name, type_ann, .. } => {
            assert_eq!(name, "ok");
            assert_eq!(*type_ann, Some(TypeAnnotation::Bool));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_let_without_type() {
    let prog = parse_program("let x = 5").unwrap();
    match &prog.stmts[0] {
        Stmt::LetDecl { type_ann, .. } => {
            assert!(type_ann.is_none());
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_mut_with_type() {
    let prog = parse_program("mut x: Field = 10").unwrap();
    match &prog.stmts[0] {
        Stmt::MutDecl { name, type_ann, .. } => {
            assert_eq!(name, "x");
            assert_eq!(*type_ann, Some(TypeAnnotation::Field));
        }
        other => panic!("expected MutDecl, got {other:?}"),
    }
}

#[test]
fn parse_public_with_type() {
    let prog = parse_program("public x: Field").unwrap();
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert_eq!(names[0].name, "x");
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn parse_witness_with_type() {
    let prog = parse_program("witness flag: Bool").unwrap();
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].name, "flag");
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::Bool));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_witness_array_with_type() {
    let prog = parse_program("witness path[3]: Field").unwrap();
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].name, "path");
            assert_eq!(names[0].array_size, Some(3));
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_public_without_type() {
    let prog = parse_program("public x").unwrap();
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert!(names[0].type_ann.is_none());
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_with_typed_params() {
    let prog = parse_program("fn hash(a: Field, b: Field) -> Field { a + b }").unwrap();
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
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::Field));
            assert_eq!(params[1].name, "b");
            assert_eq!(params[1].type_ann, Some(TypeAnnotation::Field));
            assert_eq!(*return_type, Some(TypeAnnotation::Field));
        }
        other => panic!("expected FnDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_mixed_typed_untyped_params() {
    let prog = parse_program("fn f(a: Field, b) { a + b }").unwrap();
    match &prog.stmts[0] {
        Stmt::FnDecl {
            params,
            return_type,
            ..
        } => {
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::Field));
            assert!(params[1].type_ann.is_none());
            assert!(return_type.is_none());
        }
        other => panic!("expected FnDecl, got {other:?}"),
    }
}

#[test]
fn parse_fn_expr_with_return_type() {
    let prog = parse_program("fn(x: Bool) -> Bool { !x }").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::FnExpr {
            params,
            return_type,
            ..
        }) => {
            assert_eq!(params[0].name, "x");
            assert_eq!(params[0].type_ann, Some(TypeAnnotation::Bool));
            assert_eq!(*return_type, Some(TypeAnnotation::Bool));
        }
        other => panic!("expected FnExpr, got {other:?}"),
    }
}

#[test]
fn parse_arrow_token() {
    // Ensure -> doesn't interfere with subtraction
    let prog = parse_program("a - b").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::BinOp { op: BinOp::Sub, .. }) => {}
        other => panic!("expected Sub, got {other:?}"),
    }
}

#[test]
fn parse_negative_still_works() {
    // Ensure negation still works after lexer change
    let prog = parse_program("-5").unwrap();
    match &prog.stmts[0] {
        Stmt::Expr(Expr::UnaryOp {
            op: UnaryOp::Neg, ..
        }) => {}
        other => panic!("expected Neg, got {other:?}"),
    }
}

#[test]
fn parse_type_annotation_array() {
    let prog = parse_program("let a: Field[4] = [1, 2, 3, 4]").unwrap();
    match &prog.stmts[0] {
        Stmt::LetDecl { type_ann, .. } => {
            assert_eq!(*type_ann, Some(TypeAnnotation::FieldArray(4)));
        }
        other => panic!("expected LetDecl, got {other:?}"),
    }
}

#[test]
fn parse_type_annotation_bool_array() {
    let prog = parse_program("witness flags[2]: Bool[2]").unwrap();
    match &prog.stmts[0] {
        Stmt::WitnessDecl { names, .. } => {
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::BoolArray(2)));
        }
        other => panic!("expected WitnessDecl, got {other:?}"),
    }
}

#[test]
fn parse_invalid_type_annotation() {
    assert!(parse_program("let x: Integer = 5").is_err());
}

#[test]
fn parse_multiple_public_with_types() {
    let prog = parse_program("public x: Field, y: Bool").unwrap();
    match &prog.stmts[0] {
        Stmt::PublicDecl { names, .. } => {
            assert_eq!(names.len(), 2);
            assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
            assert_eq!(names[1].type_ann, Some(TypeAnnotation::Bool));
        }
        other => panic!("expected PublicDecl, got {other:?}"),
    }
}

#[test]
fn field_and_bool_not_keywords() {
    // Field and Bool are NOT keywords, they can be used as identifiers
    let prog = parse_program("let Field = 5").unwrap();
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
    let prog = parse_program(r#"import "./utils.ach" as utils"#).unwrap();
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
    let prog = parse_program("export fn add(a, b) { a + b }").unwrap();
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
    let prog = parse_program("export let PI = 3").unwrap();
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
    let result = parse_program("export mut x = 5");
    assert!(result.is_err());
}

#[test]
fn parse_import_no_as_error() {
    // import without "as" should fail
    let result = parse_program(r#"import "./foo.ach""#);
    assert!(result.is_err());
}

#[test]
fn import_export_as_are_keywords() {
    // import, export, and as are now keywords and cannot be used as variable names
    assert!(parse_program("let import = 5").is_err());
    assert!(parse_program("let export = 5").is_err());
    assert!(parse_program("let as = 5").is_err());
}

// ====================================================================
// Error recovery tests (issue #63)
// ====================================================================

use crate::parser::parse_program_with_errors;

#[test]
fn recovery_collects_multiple_errors() {
    let source = "let x = \nlet y = 2\nlet z = ";
    let (prog, errors) = parse_program_with_errors(source);
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
    let (prog, errors) = parse_program_with_errors(source);
    assert_eq!(errors.len(), 2);
    // a errors, b succeeds, c errors
    assert!(matches!(&prog.stmts[1], Stmt::LetDecl { name, .. } if name == "b"));
}

#[test]
fn recovery_at_declaration_keywords() {
    // `)` fails; `let x = 1` ok; `let = 5` fails (missing ident); `fn add` ok
    let source = ")\nlet x = 1\nlet = 5\nfn add(a, b) { a + b }";
    let (prog, errors) = parse_program_with_errors(source);
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
    let (prog, errors) = parse_program_with_errors(source);
    assert!(errors.is_empty());
    assert_eq!(prog.stmts.len(), 3);
    assert!(prog.stmts.iter().all(|s| !matches!(s, Stmt::Error { .. })));
}

#[test]
fn recovery_error_limit() {
    // Generate 25 errors — should stop at 20
    let source = (0..25).map(|_| "let = ;").collect::<Vec<_>>().join("\n");
    let (_prog, errors) = parse_program_with_errors(&source);
    assert_eq!(errors.len(), 20);
}

#[test]
fn recovery_single_error_still_works() {
    let source = ")";
    let (prog, errors) = parse_program_with_errors(source);
    assert_eq!(errors.len(), 1);
    assert_eq!(prog.stmts.len(), 1);
    assert!(matches!(&prog.stmts[0], Stmt::Error { .. }));
}

#[test]
fn recovery_empty_source_no_errors() {
    let (prog, errors) = parse_program_with_errors("");
    assert!(errors.is_empty());
    assert!(prog.stmts.is_empty());
}

#[test]
fn recovery_interleaved_good_and_bad() {
    // `let = ` fails (missing ident); valid lets succeed
    let source = "let a = 1\nlet = 5\nlet b = 2\nlet = 5\nlet c = 3";
    let (prog, errors) = parse_program_with_errors(source);
    assert_eq!(errors.len(), 2);
    let good: Vec<_> = prog
        .stmts
        .iter()
        .filter(|s| matches!(s, Stmt::LetDecl { .. }))
        .collect();
    assert_eq!(good.len(), 3);
}
