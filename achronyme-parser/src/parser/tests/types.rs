use super::*;

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
