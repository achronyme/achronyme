//! Tests for the ProveIR compiler.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `compiler/mod.rs`.

use super::*;
use crate::ProveIrError;
use achronyme_parser::parse_program;
use memory::FieldElement;

/// Helper: parse source and compile the first expression to CircuitExpr.
fn compile_single_expr(source: &str) -> Result<CircuitExpr, ProveIrError> {
    let (program, errors) = parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    match &program.stmts[0] {
        Stmt::Expr(expr) => compiler.compile_expr(expr),
        _ => panic!("expected expression statement"),
    }
}

/// Helper: parse source with outer scope, compile an expression.
fn compile_expr_with_scope(
    source: &str,
    scope: &[(&str, CompEnvValue)],
) -> Result<CircuitExpr, ProveIrError> {
    let (program, errors) = parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    for (name, val) in scope {
        compiler.env.insert(name.to_string(), val.clone());
    }
    match &program.stmts[0] {
        Stmt::Expr(expr) => compiler.compile_expr(expr),
        _ => panic!("expected expression statement"),
    }
}

/// Helper: compile a circuit source. Automatically wraps flat format
/// (public/witness top-level declarations) into `circuit test(...) { body }`.
fn compile_circuit(source: &str) -> Result<ProveIR, ProveIrError> {
    crate::test_utils::compile_circuit(source)
}

/// Helper: compile a prove block body with outer scope captures (all scalar).
fn compile_prove_block(source: &str, outer_vars: &[&str]) -> Result<ProveIR, ProveIrError> {
    let outer = OuterScope {
        values: outer_vars
            .iter()
            .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
            .collect(),
        ..Default::default()
    };
    ProveIrCompiler::<Bn254Fr>::compile_prove_block(source, &outer)
}

mod audit;
mod capture;
mod circom_dispatch;
mod circom_table;
mod control_flow;
mod expr_access_methods_builtins;
mod expr_basic;
mod functions;
mod indexed_arrays;
mod integration;
mod mut_ssa;
mod outer_scope;
mod statements;
