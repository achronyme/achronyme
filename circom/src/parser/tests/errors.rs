use super::*;

// ── Error recovery ───────────────────────────────────────────────

#[test]
fn error_recovery_continues() {
    let src = r#"
            template T() {
                signal input a;
                invalid syntax here;
                signal output b;
            }
        "#;
    let (prog, errors) = parse_circom(src).unwrap();
    assert!(!errors.is_empty());
    // Should still have parsed template with some stmts
    assert_eq!(prog.definitions.len(), 1);
}

// ── Malformed input error codes ──────────────────────────────────

#[test]
fn error_recovery_has_e300_code() {
    let src = r#"
            template T() {
                signal input a;
                invalid syntax here;
                signal output b;
            }
        "#;
    let (_, errors) = parse_circom(src).unwrap();
    assert_eq!(error_code(&errors).as_deref(), Some("E300"));
}

#[test]
fn unknown_pragma_e304() {
    let err = parse_circom("pragma unknown;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E304"));
}

#[test]
fn invalid_version_e305() {
    let err = parse_circom("pragma circom abc;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E305"));
}

#[test]
fn unexpected_top_level_e306() {
    let src = "var x = 5;";
    let (_, errors) = parse_circom(src).unwrap();
    assert!(!errors.is_empty());
    assert_eq!(error_code(&errors).as_deref(), Some("E306"));
}

#[test]
fn missing_semicolon_e300() {
    let err = parse_circom("pragma circom 2.1.6").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn missing_template_body_e300() {
    let err = parse_circom("template T()").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn template_missing_name_e300() {
    let src = "template () { signal input a; }";
    let err = parse_circom(src).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn function_missing_body_e300() {
    let err = parse_circom("function f()").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn component_not_main_e306() {
    let src = "component other = T();";
    let (_, errors) = parse_circom(src).unwrap();
    assert!(!errors.is_empty());
    assert_eq!(error_code(&errors).as_deref(), Some("E306"));
}

#[test]
fn multiple_errors_collected() {
    let src = r#"
            template T() {
                signal input;
                signal output;
                var = 5;
            }
        "#;
    let (_, errors) = parse_circom(src).unwrap();
    assert!(
        errors.len() >= 2,
        "expected multiple errors, got {}",
        errors.len()
    );
    for err in &errors {
        assert!(err.code.is_some(), "error without code: {:?}", err);
    }
}

#[test]
fn error_recovery_collects_multiple_stmts() {
    let src = r#"
            template T() {
                signal input a;
                badstmt1 + ;
                signal output b;
                another bad;
                signal output c;
            }
        "#;
    let (prog, errors) = parse_circom(src).unwrap();
    assert!(errors.len() >= 2);
    if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
        // Should have recovered some valid stmts
        let valid_count = t
            .body
            .stmts
            .iter()
            .filter(|s| !matches!(s, crate::ast::Stmt::Error { .. }))
            .count();
        assert!(
            valid_count >= 2,
            "expected at least 2 valid stmts after recovery"
        );
    }
}

#[test]
fn include_missing_string_e300() {
    let err = parse_circom("include 42;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn main_component_missing_template_e300() {
    let err = parse_circom("component main = ;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn incomplete_version_e300() {
    let err = parse_circom("pragma circom 2.1;").unwrap_err();
    // Missing patch version → expects `.` but finds `;`
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn empty_source_no_errors() {
    let (prog, errors) = parse_circom("").unwrap();
    assert!(errors.is_empty());
    assert!(prog.definitions.is_empty());
    assert!(prog.main_component.is_none());
}

#[test]
fn only_comments_no_errors() {
    let (_, errors) = parse_circom("// just a comment\n/* block */").unwrap();
    assert!(errors.is_empty());
}

#[test]
fn unclosed_block_in_template() {
    let err = parse_circom("template T() { signal input a;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E300"));
}

#[test]
fn expression_where_stmt_expected() {
    let src = r#"
            template T() {
                signal input a;
                42;
            }
        "#;
    // `42;` should parse as Stmt::Expr, which is valid Circom
    let (_, errors) = parse_circom(src).unwrap();
    assert!(errors.is_empty());
}

/// Hundreds of nested `[` would overflow the recursive-descent
/// stack via `parse_expr_bp → parse_prefix → parse_atom →
/// parse_array_lit → parse_expr_list → parse_expr`. The
/// expression-depth cap returns a graceful failure instead.
#[test]
fn deeply_nested_exprs_do_not_overflow() {
    let inner: String = "[".repeat(2000);
    let src = format!("template T() {{ signal a; a <-- {inner};");
    let _ = parse_circom(&src);
}

/// Hundreds of nested `{` would overflow via `parse_block →
/// parse_stmt → parse_block`. The block-depth cap returns a
/// graceful failure instead.
#[test]
fn deeply_nested_blocks_do_not_overflow() {
    let inner: String = "{".repeat(2000);
    let src = format!("template T() {inner}");
    let _ = parse_circom(&src);
}
