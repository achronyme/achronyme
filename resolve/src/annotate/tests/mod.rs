use super::*;
use crate::error::ResolveError;
use crate::module_graph::{LoadedModule, ModuleGraph, ModuleId, ModuleSource};
use crate::symbol::{CallableKind, ConstKind};
use crate::table::SymbolTable;
use achronyme_parser::ast::{ElseBranch, Expr, ExprId, ForIterable, Stmt};
use achronyme_parser::parse_program;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

mod annotation;
mod prove_shapes;
mod registration;

/// In-memory `ModuleSource` mirroring the one in `module_graph::tests`.
/// Duplicated here to keep the two test modules independent; a
/// shared helper would cost more than the 40 lines of copy.
#[derive(Default)]
struct MockSource {
    files: HashMap<String, String>,
}

impl MockSource {
    fn add(&mut self, name: &str, source: &str) {
        self.files.insert(name.to_string(), source.to_string());
    }
}

impl ModuleSource for MockSource {
    fn canonicalize(
        &mut self,
        _importer: Option<&Path>,
        relative: &str,
    ) -> Result<PathBuf, String> {
        if self.files.contains_key(relative) {
            Ok(PathBuf::from(relative))
        } else {
            Err(format!("no such module `{relative}`"))
        }
    }

    fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String> {
        let key = canonical.to_string_lossy().into_owned();
        let source = self
            .files
            .get(&key)
            .ok_or_else(|| format!("missing source for `{key}`"))?;
        let (program, errors) = parse_program(source);
        if !errors.is_empty() {
            return Err(format!("parse errors in `{key}`: {}", errors[0].message));
        }
        // Mirror the ir::ModuleLoader contract: walk top-level
        // exports and flatten to a name list.
        let exported_names = program
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Export { inner, .. } => match inner.as_ref() {
                    Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        Ok(LoadedModule {
            program,
            exported_names,
        })
    }
}

// ======================================================================
// annotate_program
// ======================================================================

use crate::builtins::BuiltinRegistry;
use achronyme_parser::ast::{Program, TypedParam};

/// Walk every Expr in a Program, calling `f` on each. Used by the
/// annotate-pass tests to hand-pick specific nodes (by kind + name) and
/// assert on their annotations without building a full visitor.
fn visit_program<F: FnMut(&Expr)>(program: &Program, mut f: F) {
    for stmt in &program.stmts {
        visit_stmt(stmt, &mut f);
    }
}

fn visit_stmt<F: FnMut(&Expr)>(stmt: &Stmt, f: &mut F) {
    match stmt {
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => visit_expr(value, f),
        Stmt::Assignment { target, value, .. } => {
            visit_expr(target, f);
            visit_expr(value, f);
        }
        Stmt::FnDecl { body, .. } | Stmt::CircuitDecl { body, .. } => {
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Stmt::Print { value, .. } => visit_expr(value, f),
        Stmt::Return { value: Some(v), .. } => visit_expr(v, f),
        Stmt::Expr(e) => visit_expr(e, f),
        Stmt::Export { inner, .. } => visit_stmt(inner, f),
        _ => {}
    }
}

fn visit_expr<F: FnMut(&Expr)>(expr: &Expr, f: &mut F) {
    f(expr);
    match expr {
        Expr::BinOp { lhs, rhs, .. } => {
            visit_expr(lhs, f);
            visit_expr(rhs, f);
        }
        Expr::UnaryOp { operand, .. } => visit_expr(operand, f),
        Expr::Call { callee, args, .. } => {
            visit_expr(callee, f);
            for a in args {
                visit_expr(&a.value, f);
            }
        }
        Expr::Index { object, index, .. } => {
            visit_expr(object, f);
            visit_expr(index, f);
        }
        Expr::DotAccess { object, .. } => visit_expr(object, f),
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            visit_expr(condition, f);
            for s in &then_block.stmts {
                visit_stmt(s, f);
            }
            match else_branch {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        visit_stmt(s, f);
                    }
                }
                Some(ElseBranch::If(e)) => visit_expr(e, f),
                None => {}
            }
        }
        Expr::For { iterable, body, .. } => {
            match iterable {
                ForIterable::ExprRange { end, .. } => visit_expr(end, f),
                ForIterable::Expr(e) => visit_expr(e, f),
                _ => {}
            }
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::While {
            condition, body, ..
        } => {
            visit_expr(condition, f);
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Forever { body, .. } | Expr::FnExpr { body, .. } | Expr::Prove { body, .. } => {
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Block { block, .. } => {
            for s in &block.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                visit_expr(e, f);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                visit_expr(v, f);
            }
        }
        _ => {}
    }
}

/// Find every `Expr::Ident { name: expected }` in a module and return
/// their [`ExprId`]s in source order.
fn find_idents(program: &Program, expected: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::Ident { id, name, .. } = e {
            if name == expected {
                out.push(*id);
            }
        }
    });
    out
}

fn find_static_accesses(program: &Program, type_name: &str, member: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::StaticAccess {
            id,
            type_name: t,
            member: m,
            ..
        } = e
        {
            if t == type_name && m == member {
                out.push(*id);
            }
        }
    });
    out
}

fn find_dot_accesses(program: &Program, object_name: &str, field: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::DotAccess {
            id,
            object,
            field: f,
            ..
        } = e
        {
            if f == field {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if name == object_name {
                        out.push(*id);
                    }
                }
            }
        }
    });
    out
}

/// Build a fresh table with the production builtin registry plus
/// the given graph's module symbols.
fn build_full_table(graph: &ModuleGraph) -> SymbolTable {
    let mut table = SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
    register_builtins(&mut table);
    register_all(&mut table, graph).expect("register_all");
    table
}
