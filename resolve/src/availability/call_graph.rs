use std::collections::HashMap;

use achronyme_parser::ast::{Block, ElseBranch, Expr, ForIterable, Stmt};

use crate::annotate::{AnnotationKey, ResolvedProgram};
use crate::module_graph::{ModuleGraph, ModuleId};
use crate::symbol::{CallableKind, SymbolId};
use crate::table::SymbolTable;

use super::FnCallInfo;

pub(super) fn build_call_graph(
    table: &SymbolTable,
    graph: &ModuleGraph,
    resolved: &ResolvedProgram,
) -> HashMap<SymbolId, FnCallInfo> {
    let mut result = HashMap::new();

    for (sym_id, kind) in table.iter() {
        let (module, stmt_index) = match kind {
            CallableKind::UserFn {
                module, stmt_index, ..
            } => (*module, *stmt_index),
            _ => continue,
        };

        let node = graph.get(module);
        let stmt = match node.program.stmts.get(stmt_index as usize) {
            Some(s) => s,
            None => continue,
        };

        let body = match extract_fn_body(stmt) {
            Some(b) => b,
            None => continue,
        };

        let info = collect_calls_from_body(body, module, &resolved.annotations);
        result.insert(sym_id, info);
    }

    result
}

/// Unwrap `Export { FnDecl { body } }` or `FnDecl { body }` to get the
/// function body. Returns `None` for non-FnDecl statements.
fn extract_fn_body(stmt: &Stmt) -> Option<&Block> {
    match stmt {
        Stmt::Export { inner, .. } => match inner.as_ref() {
            Stmt::FnDecl { body, .. } => Some(body),
            _ => None,
        },
        Stmt::FnDecl { body, .. } => Some(body),
        _ => None,
    }
}

fn collect_calls_from_body(
    body: &Block,
    module: ModuleId,
    annotations: &HashMap<AnnotationKey, SymbolId>,
) -> FnCallInfo {
    let mut info = FnCallInfo {
        direct_calls: Vec::new(),
        has_prove_block: false,
    };
    walk_block(&mut info, body, module, annotations);
    info.direct_calls.sort();
    info.direct_calls.dedup();
    info
}

fn walk_block(
    info: &mut FnCallInfo,
    block: &Block,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    for stmt in &block.stmts {
        walk_stmt(info, stmt, module, anns);
    }
}

fn walk_stmt(
    info: &mut FnCallInfo,
    stmt: &Stmt,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    match stmt {
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            walk_expr(info, value, module, anns);
        }
        Stmt::Assignment { target, value, .. } => {
            walk_expr(info, target, module, anns);
            walk_expr(info, value, module, anns);
        }
        Stmt::FnDecl { body, .. } => {
            walk_block(info, body, module, anns);
        }
        Stmt::CircuitDecl { .. } => {
            info.has_prove_block = true;
        }
        Stmt::Print { value, .. } => walk_expr(info, value, module, anns),
        Stmt::Return { value: Some(v), .. } => walk_expr(info, v, module, anns),
        Stmt::Expr(e) => walk_expr(info, e, module, anns),
        Stmt::Export { inner, .. } => walk_stmt(info, inner, module, anns),
        _ => {}
    }
}

fn walk_expr(
    info: &mut FnCallInfo,
    expr: &Expr,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    // Collect annotation if this expression resolved to a known symbol.
    let key = (module, expr.id());
    if let Some(&sym) = anns.get(&key) {
        info.direct_calls.push(sym);
    }

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
            walk_expr(info, lhs, module, anns);
            walk_expr(info, rhs, module, anns);
        }
        Expr::UnaryOp { operand, .. } => {
            walk_expr(info, operand, module, anns);
        }
        Expr::Call { callee, args, .. } => {
            walk_expr(info, callee, module, anns);
            for arg in args {
                walk_expr(info, &arg.value, module, anns);
            }
        }
        Expr::Index { object, index, .. } => {
            walk_expr(info, object, module, anns);
            walk_expr(info, index, module, anns);
        }
        Expr::DotAccess { object, .. } => {
            walk_expr(info, object, module, anns);
        }
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            walk_expr(info, condition, module, anns);
            walk_block(info, then_block, module, anns);
            match else_branch {
                Some(ElseBranch::Block(b)) => walk_block(info, b, module, anns),
                Some(ElseBranch::If(e)) => walk_expr(info, e, module, anns),
                None => {}
            }
        }
        Expr::For { iterable, body, .. } => {
            match iterable {
                ForIterable::Range { .. } => {}
                ForIterable::ExprRange { end, .. } => walk_expr(info, end, module, anns),
                ForIterable::Expr(e) => walk_expr(info, e, module, anns),
            }
            walk_block(info, body, module, anns);
        }
        Expr::While {
            condition, body, ..
        } => {
            walk_expr(info, condition, module, anns);
            walk_block(info, body, module, anns);
        }
        Expr::Forever { body, .. } => walk_block(info, body, module, anns),
        Expr::Block { block, .. } => walk_block(info, block, module, anns),
        Expr::FnExpr { body, .. } => {
            walk_block(info, body, module, anns);
        }
        Expr::Prove { .. } => {
            // prove {} is a VM expression that produces a proof value.
            // Its inner body is compiled by ProveIR, so do not walk into it.
            info.has_prove_block = true;
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                walk_expr(info, e, module, anns);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                walk_expr(info, v, module, anns);
            }
        }
    }
}
