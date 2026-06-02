use super::*;

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
