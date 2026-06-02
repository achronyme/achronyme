use super::*;

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
