//! Shared test helpers for the lowering module.
//!
//! Provides common parsing and environment setup functions used across
//! expression, statement, and utility tests.

#![cfg(test)]

use std::collections::HashMap;

use crate::ast::{self, Expr};
use crate::parser::parse_circom;

use super::context::LoweringContext;
use super::env::LoweringEnv;

/// Parse a Circom expression inside a template var init.
///
/// Wraps the expression in `template T() { var _x = <expr>; }` to
/// produce a valid program, then extracts the initializer.
pub fn parse_expr(expr_src: &str) -> Expr {
    let src = format!("template T() {{ var _x = {expr_src}; }}");
    let (prog, errors) = parse_circom(&src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);
    match &prog.definitions[0] {
        ast::Definition::Template(t) => match &t.body.stmts[0] {
            ast::Stmt::VarDecl { init: Some(e), .. } => e.clone(),
            other => panic!("expected VarDecl, got {:?}", other),
        },
        _ => panic!("expected template"),
    }
}

/// Parse a complete Circom program.
pub fn parse_program(src: &str) -> ast::CircomProgram {
    let (prog, errors) = parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);
    prog
}

/// Build a functions map from a parsed program.
pub fn extract_functions(prog: &ast::CircomProgram) -> HashMap<&str, &ast::FunctionDef> {
    let mut fns = HashMap::new();
    for def in &prog.definitions {
        if let ast::Definition::Function(f) = def {
            fns.insert(f.name.as_str(), f);
        }
    }
    fns
}

/// Create a standard test environment with common signal names pre-registered.
pub fn make_env() -> LoweringEnv {
    let mut env = LoweringEnv::new();
    env.inputs.insert("in".to_string());
    env.inputs.insert("a".to_string());
    env.inputs.insert("b".to_string());
    env.locals.insert("x".to_string());
    env.locals.insert("out".to_string());
    env.locals.insert("bits".to_string());
    env.captures.insert("n".to_string());
    env
}

/// Create an empty lowering context for testing.
pub fn make_ctx() -> LoweringContext<'static> {
    LoweringContext::empty()
}
