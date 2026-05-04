//! Circom parser — hand-written recursive descent with Pratt expression parsing.
//!
//! Public API: [`parse_circom`] parses a complete `.circom` file.

mod core;
mod exprs;
mod stmts;
mod tables;

use diagnostics::{Diagnostic, ParseError};

use crate::ast::CircomProgram;
use crate::lexer::Lexer;

/// Parse a complete Circom source file.
///
/// Returns `(program, diagnostics)`. On partial failure, the program may
/// contain `Stmt::Error` / `Expr::Error` placeholders and the diagnostics
/// will list the errors encountered.
pub fn parse_circom(source: &str) -> Result<(CircomProgram, Vec<Diagnostic>), ParseError> {
    let tokens = Lexer::tokenize(source)?;
    let mut parser = core::Parser::new(tokens);
    let program = parser.do_parse_program()?;
    let errors = parser.take_errors();
    Ok((program, errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinOp, Expr, PostfixOp};

    fn parse(src: &str) -> CircomProgram {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        if !errors.is_empty() {
            panic!("parse errors: {:?}", errors);
        }
        prog
    }

    // ── Pragma ───────────────────────────────────────────────────────

    #[test]
    fn parse_pragma_version() {
        let prog = parse("pragma circom 2.1.6;");
        let v = prog.version.unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 1, 6));
    }

    #[test]
    fn parse_pragma_custom_templates() {
        let prog = parse("pragma custom_templates;");
        assert!(prog.custom_templates);
    }

    // ── Include ──────────────────────────────────────────────────────

    #[test]
    fn parse_include() {
        let prog = parse(r#"include "circomlib/poseidon.circom";"#);
        assert_eq!(prog.includes.len(), 1);
        assert_eq!(prog.includes[0].path, "circomlib/poseidon.circom");
    }

    // ── Template ─────────────────────────────────────────────────────

    #[test]
    fn parse_simple_template() {
        let prog = parse(
            r#"
            template Multiplier(n) {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
            "#,
        );
        assert_eq!(prog.definitions.len(), 1);
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert_eq!(t.name, "Multiplier");
            assert_eq!(t.params, vec!["n"]);
            assert_eq!(t.body.stmts.len(), 4); // 3 signal decls + 1 substitution
        } else {
            panic!("expected template");
        }
    }

    #[test]
    fn parse_template_with_modifiers() {
        let prog = parse("template custom parallel MyGate() { signal input a; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(t.modifiers.custom);
            assert!(t.modifiers.parallel);
        } else {
            panic!("expected template");
        }
    }

    #[test]
    fn parse_template_extern_c() {
        let prog = parse("template custom extern_c MyGate() { signal input a; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(t.modifiers.custom);
            assert!(t.modifiers.extern_c);
            assert!(!t.modifiers.parallel);
        } else {
            panic!("expected template");
        }
    }

    // ── Function ─────────────────────────────────────────────────────

    #[test]
    fn parse_function() {
        let prog = parse(
            r#"
            function add(a, b) {
                return a + b;
            }
            "#,
        );
        if let crate::ast::Definition::Function(f) = &prog.definitions[0] {
            assert_eq!(f.name, "add");
            assert_eq!(f.params, vec!["a", "b"]);
        } else {
            panic!("expected function");
        }
    }

    // ── Main component ───────────────────────────────────────────────

    #[test]
    fn parse_main_component() {
        let prog = parse("component main {public [a, b]} = Multiplier(2);");
        let main = prog.main_component.unwrap();
        assert_eq!(main.public_signals, vec!["a", "b"]);
        assert_eq!(main.template_name, "Multiplier");
        assert_eq!(main.template_args.len(), 1);
    }

    #[test]
    fn parse_main_no_public() {
        let prog = parse("component main = Adder(3);");
        let main = prog.main_component.unwrap();
        assert!(main.public_signals.is_empty());
        assert_eq!(main.template_name, "Adder");
    }

    // ── Signal declarations ──────────────────────────────────────────

    #[test]
    fn parse_signal_input() {
        let prog = parse("template T() { signal input x; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl {
                signal_type,
                declarations,
                ..
            } = &t.body.stmts[0]
            {
                assert_eq!(*signal_type, crate::ast::SignalType::Input);
                assert_eq!(declarations[0].name, "x");
            } else {
                panic!("expected signal decl");
            }
        }
    }

    #[test]
    fn parse_signal_with_init() {
        let prog = parse("template T() { signal output c <== 42; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl { init, .. } = &t.body.stmts[0] {
                assert!(init.is_some());
            }
        }
    }

    #[test]
    fn parse_signal_array() {
        let prog = parse("template T() { signal input x[3]; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl { declarations, .. } = &t.body.stmts[0] {
                assert_eq!(declarations[0].dimensions.len(), 1);
            }
        }
    }

    #[test]
    fn parse_signal_with_tags() {
        let prog = parse("template T() { signal input {binary} x; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl { tags, .. } = &t.body.stmts[0] {
                assert_eq!(tags, &["binary"]);
            }
        }
    }

    #[test]
    fn parse_reversed_signal_decl() {
        let prog = parse("template T() { input signal x; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl { signal_type, .. } = &t.body.stmts[0] {
                assert_eq!(*signal_type, crate::ast::SignalType::Input);
            }
        }
    }

    // ── Substitutions ────────────────────────────────────────────────

    #[test]
    fn parse_constraint_assign() {
        let prog = parse("template T() { signal output c; c <== 1; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Substitution { op, .. } = &t.body.stmts[1] {
                assert_eq!(*op, crate::ast::AssignOp::ConstraintAssign);
            }
        }
    }

    #[test]
    fn parse_signal_assign() {
        let prog = parse("template T() { signal x; x <-- 1; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Substitution { op, .. } = &t.body.stmts[1] {
                assert_eq!(*op, crate::ast::AssignOp::SignalAssign);
            }
        }
    }

    #[test]
    fn parse_constraint_eq() {
        let prog = parse("template T() { signal x; signal y; x === y; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(matches!(
                &t.body.stmts[2],
                crate::ast::Stmt::ConstraintEq { .. }
            ));
        }
    }

    // ── Control flow ─────────────────────────────────────────────────

    #[test]
    fn parse_for_loop() {
        let prog = parse(
            r#"
            template T() {
                var x = 0;
                for (var i = 0; i < 10; i++) {
                    x += 1;
                }
            }
            "#,
        );
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(matches!(&t.body.stmts[1], crate::ast::Stmt::For { .. }));
        }
    }

    #[test]
    fn parse_if_else() {
        let prog = parse(
            r#"
            template T() {
                var x = 0;
                if (x == 0) {
                    x = 1;
                } else {
                    x = 2;
                }
            }
            "#,
        );
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(matches!(&t.body.stmts[1], crate::ast::Stmt::IfElse { .. }));
        }
    }

    #[test]
    fn parse_while_loop() {
        let prog = parse(
            r#"
            template T() {
                var i = 0;
                while (i < 5) { i += 1; }
            }
            "#,
        );
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(matches!(&t.body.stmts[1], crate::ast::Stmt::While { .. }));
        }
    }

    // ── Expressions ──────────────────────────────────────────────────

    #[test]
    fn parse_binary_ops() {
        let prog = parse("template T() { var x = 1 + 2 * 3; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::VarDecl {
                init: Some(expr), ..
            } = &t.body.stmts[0]
            {
                // Should be Add(1, Mul(2, 3)) due to precedence
                if let Expr::BinOp { op, .. } = expr {
                    assert_eq!(*op, BinOp::Add);
                } else {
                    panic!("expected BinOp");
                }
            }
        }
    }

    #[test]
    fn parse_ternary() {
        let prog = parse("template T() { var x = 1 == 0 ? 2 : 3; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::VarDecl {
                init: Some(expr), ..
            } = &t.body.stmts[0]
            {
                assert!(matches!(expr, Expr::Ternary { .. }));
            }
        }
    }

    #[test]
    fn parse_array_literal() {
        let prog = parse("template T() { var x = [1, 2, 3]; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::VarDecl {
                init: Some(expr), ..
            } = &t.body.stmts[0]
            {
                if let Expr::ArrayLit { elements, .. } = expr {
                    assert_eq!(elements.len(), 3);
                } else {
                    panic!("expected array lit");
                }
            }
        }
    }

    #[test]
    fn parse_call_expr() {
        let prog = parse("template T() { var x = f(1, 2); }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::VarDecl {
                init: Some(expr), ..
            } = &t.body.stmts[0]
            {
                assert!(matches!(expr, Expr::Call { .. }));
            }
        }
    }

    #[test]
    fn parse_index_expr() {
        let prog = parse("template T() { var x; x = a[0]; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Substitution { value, .. } = &t.body.stmts[1] {
                assert!(matches!(value, Expr::Index { .. }));
            }
        }
    }

    #[test]
    fn parse_dot_access() {
        let prog = parse("template T() { signal output x; x <== c.out; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Substitution { value, .. } = &t.body.stmts[1] {
                assert!(matches!(value, Expr::DotAccess { .. }));
            }
        }
    }

    #[test]
    fn parse_postfix_increment() {
        let prog = parse("template T() { var i = 0; i++; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Expr { expr, .. } = &t.body.stmts[1] {
                assert!(matches!(
                    expr,
                    Expr::PostfixOp {
                        op: PostfixOp::Increment,
                        ..
                    }
                ));
            }
        }
    }

    #[test]
    fn parse_compound_assign() {
        let prog = parse("template T() { var i = 0; i += 1; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert!(matches!(
                &t.body.stmts[1],
                crate::ast::Stmt::CompoundAssign { .. }
            ));
        }
    }

    // ── Realistic Circom ─────────────────────────────────────────────

    #[test]
    fn parse_realistic_template() {
        let src = r#"
pragma circom 2.1.6;

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in != 0 ? 1 / in : 0;

    out <== -in * inv + 1;
    in * out === 0;
}

component main = IsZero();
"#;
        let (prog, errors) = parse_circom(src).unwrap();
        assert!(errors.is_empty(), "errors: {:?}", errors);
        assert_eq!(prog.definitions.len(), 1);
        assert!(prog.main_component.is_some());
    }

    #[test]
    fn parse_anonymous_component() {
        let prog = parse(
            r#"
            template T() {
                signal input a;
                signal output b;
                b <== Multiplier(2)(a, a);
            }
            "#,
        );
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::Substitution { value, .. } = &t.body.stmts[2] {
                assert!(matches!(value, Expr::AnonComponent { .. }));
            }
        }
    }

    // ── Error recovery ───────────────────────────────────────────────

    #[test]
    fn parse_signal_tag_value_assignment() {
        // signal.tag = expr parses as Substitution with DotAccess target
        let prog = parse("template T() { signal output {maxbit} x; x.maxbit = 8; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            assert_eq!(t.body.stmts.len(), 2);
            // Second stmt is a substitution: x.maxbit = 8
            if let crate::ast::Stmt::Substitution { target, op, .. } = &t.body.stmts[1] {
                assert!(matches!(op, crate::ast::AssignOp::Assign));
                assert!(
                    matches!(target, crate::ast::Expr::DotAccess { field, .. } if field == "maxbit")
                );
            } else {
                panic!("expected Substitution for tag value assignment");
            }
        }
    }

    #[test]
    fn parse_signal_multiple_tags() {
        let prog = parse("template T() { signal input {binary, maxbit} x; }");
        if let crate::ast::Definition::Template(t) = &prog.definitions[0] {
            if let crate::ast::Stmt::SignalDecl { tags, .. } = &t.body.stmts[0] {
                assert_eq!(tags, &["binary", "maxbit"]);
            }
        }
    }

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

    fn error_code(errors: &[diagnostics::Diagnostic]) -> Option<String> {
        errors.first().and_then(|d| d.code.clone())
    }

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
}
