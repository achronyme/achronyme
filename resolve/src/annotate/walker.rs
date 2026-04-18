//! AST walker — the meat of the Phase 3C.2 annotate pass.
//!
//! Five visitors, each `pub(super)`:
//!
//! - [`walk_stmt`] — top-level dispatch on every `Stmt` variant. Walks
//!   embedded expressions, manages function/circuit-body scopes, and
//!   handles `prove`-depth bookkeeping.
//! - [`walk_block_stmts`] — flat statement walk *without* scope
//!   management. Used by callers that already pushed a scope (fn
//!   bodies, circuit bodies, for-loop bodies).
//! - [`walk_block_scoped`] — convenience that pushes a scope before
//!   delegating to `walk_block_stmts`. Used for `if/else` arms,
//!   plain `{ … }` blocks, and other lexical scopes the walker
//!   visits transparently.
//! - [`walk_expr`] — the big match on every `Expr` variant. Handles
//!   resolution + annotation of `Ident` / `StaticAccess` / `DotAccess`
//!   plus prove-block shape diagnostics on `Index` / `DotAccess`.
//! - [`walk_call`] — dispatches the `Call` variant of `walk_expr`.
//!   Split out because the callee + each positional arg get
//!   prove-block shape checks before being walked.

use achronyme_parser::ast::{Block, ElseBranch, Expr, ForIterable, Span, Stmt};

use super::classify::{classify_let_rhs, is_dynamic_fn_if, is_namespace_alias_ident};
use super::context::{AnnotateCtx, LocalKind};
use super::resolve::{resolve_dot_access, resolve_ident, resolve_static_access};
use crate::error::UnsupportedShape;

pub(super) fn walk_stmt(ctx: &mut AnnotateCtx, stmt: &Stmt) {
    match stmt {
        Stmt::LetDecl { name, value, .. } | Stmt::MutDecl { name, value, .. } => {
            walk_expr(ctx, value);
            // Classify the RHS for FnAlias + shape-diagnostic tracking.
            let kind = classify_let_rhs(ctx, value);
            ctx.add_local(name, kind);
        }
        Stmt::Assignment { target, value, .. } => {
            walk_expr(ctx, target);
            walk_expr(ctx, value);
        }
        Stmt::FnDecl { params, body, .. } => {
            // Params and the body share one scope in Achronyme — a
            // top-level `let` inside the body shadows a param.
            ctx.push_scope();
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Stmt::CircuitDecl { params, body, .. } => {
            ctx.push_scope();
            ctx.in_prove_depth += 1;
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.in_prove_depth -= 1;
            ctx.pop_scope();
        }
        Stmt::Print { value, .. } => walk_expr(ctx, value),
        Stmt::Return { value: Some(v), .. } => walk_expr(ctx, v),
        Stmt::Return { value: None, .. } => {}
        Stmt::Expr(e) => walk_expr(ctx, e),
        Stmt::Export { inner, .. } => walk_stmt(ctx, inner),
        // PublicDecl, WitnessDecl, Import, SelectiveImport, ExportList,
        // ImportCircuit, Break, Continue, Error — no embedded exprs to
        // walk.
        _ => {}
    }
}

/// Walk the statements of a [`Block`] **without** managing its scope.
/// Used when the caller has already pushed a scope (e.g. the fn-body
/// walker that wants params and body in the same scope).
pub(super) fn walk_block_stmts(ctx: &mut AnnotateCtx, block: &Block) {
    for stmt in &block.stmts {
        walk_stmt(ctx, stmt);
    }
}

/// Walk a [`Block`] as an independent lexical scope. Pushes, walks,
/// pops.
pub(super) fn walk_block_scoped(ctx: &mut AnnotateCtx, block: &Block) {
    ctx.push_scope();
    walk_block_stmts(ctx, block);
    ctx.pop_scope();
}

pub(super) fn walk_expr(ctx: &mut AnnotateCtx, expr: &Expr) {
    // Step 1: try to resolve the expression itself.
    let module_id = ctx.module.id;
    match expr {
        Expr::Ident { id, name, .. } => {
            if let Some(sid) = resolve_ident(ctx, name) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        Expr::StaticAccess {
            id,
            type_name,
            member,
            ..
        } => {
            if let Some(sid) = resolve_static_access(ctx, type_name, member) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        Expr::DotAccess {
            id, object, field, ..
        } => {
            if let Some(sid) = resolve_dot_access(ctx, object, field) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        _ => {}
    }

    // Step 2: recurse into children regardless of whether we resolved
    // step 1. Annotating the parent does NOT short-circuit the walk —
    // a `DotAccess { object: Ident(alias), .. }` still has its inner
    // `Ident` walked, which is harmless because the alias won't resolve
    // as an ident (no module symbol shares its name by construction).
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
            walk_expr(ctx, lhs);
            walk_expr(ctx, rhs);
        }
        Expr::UnaryOp { operand, .. } => walk_expr(ctx, operand),
        Expr::Call {
            callee, args, span, ..
        } => walk_call(ctx, callee, args, span),
        Expr::Index {
            object,
            index,
            span,
            ..
        } => {
            // Inside a prove block, indexing into a local Map literal
            // is `RuntimeMapAccess`. Plain arrays (witness arrays,
            // fixed-size `[Field; N]` style bindings) don't bind as
            // `LocalKind::RuntimeMap`, so they pass through.
            if ctx.in_prove_depth > 0 {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if matches!(ctx.lookup_local(name), Some(LocalKind::RuntimeMap)) {
                        ctx.push_diagnostic(
                            span.clone(),
                            UnsupportedShape::RuntimeMapAccess,
                            "indexing a runtime map inside a prove block",
                        );
                    }
                }
            }
            walk_expr(ctx, object);
            walk_expr(ctx, index);
        }
        Expr::DotAccess {
            object,
            field: _,
            span,
            ..
        } => {
            // Standalone DotAccess (not the callee of a Call — the
            // Call arm handles that path). Inside a prove block,
            // `m.field` where `m` is a local Map literal is a
            // `RuntimeMapAccess`.
            if ctx.in_prove_depth > 0 {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if matches!(ctx.lookup_local(name), Some(LocalKind::RuntimeMap)) {
                        ctx.push_diagnostic(
                            span.clone(),
                            UnsupportedShape::RuntimeMapAccess,
                            "field access on a runtime map inside a prove block",
                        );
                    }
                }
            }
            walk_expr(ctx, object);
        }
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            walk_expr(ctx, condition);
            walk_block_scoped(ctx, then_block);
            match else_branch {
                Some(ElseBranch::Block(b)) => walk_block_scoped(ctx, b),
                Some(ElseBranch::If(e)) => walk_expr(ctx, e),
                None => {}
            }
        }
        Expr::For {
            var,
            iterable,
            body,
            ..
        } => {
            match iterable {
                ForIterable::Range { .. } => {}
                ForIterable::ExprRange { end, .. } => walk_expr(ctx, end),
                ForIterable::Expr(e) => walk_expr(ctx, e),
            }
            ctx.push_scope();
            ctx.add_local(var, LocalKind::Plain);
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Expr::While {
            condition, body, ..
        } => {
            walk_expr(ctx, condition);
            walk_block_scoped(ctx, body);
        }
        Expr::Forever { body, .. } => walk_block_scoped(ctx, body),
        Expr::Block { block, .. } => walk_block_scoped(ctx, block),
        Expr::FnExpr { params, body, .. } => {
            ctx.push_scope();
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Expr::Prove { params, body, .. } => {
            ctx.push_scope();
            ctx.in_prove_depth += 1;
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.in_prove_depth -= 1;
            ctx.pop_scope();
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                walk_expr(ctx, e);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                walk_expr(ctx, v);
            }
        }
    }
}

/// Walk a `Call { callee, args }` with prove-block shape checks.
/// This is broken out of [`walk_expr`] because the callee is inspected
/// for [`UnsupportedShape::RuntimeMethodChain`] + [`UnsupportedShape::DynamicFnValue`]
/// *before* being walked, and each argument is inspected for
/// [`UnsupportedShape::NonStaticFnArg`].
pub(super) fn walk_call(
    ctx: &mut AnnotateCtx,
    callee: &Expr,
    args: &[achronyme_parser::ast::CallArg],
    call_span: &Span,
) {
    if ctx.in_prove_depth > 0 {
        // DynamicFnValue: calling a local that was bound to an
        // if/else of fn references.
        if let Expr::Ident { name, span, .. } = callee {
            if matches!(ctx.lookup_local(name), Some(LocalKind::DynamicFn)) {
                ctx.push_diagnostic(
                    span.clone(),
                    UnsupportedShape::DynamicFnValue,
                    "calling a local bound to a dynamic fn value inside a prove block",
                );
            }
        }
        // RuntimeMethodChain: `expr.method()` where `expr` is not a
        // namespace import alias. Namespace calls via `l.foo()` use
        // the `Expr::DotAccess` path and resolve to a module symbol;
        // non-namespace DotAccess callees are runtime method dispatch
        // which prove blocks can't model.
        if let Expr::DotAccess { object, span, .. } = callee {
            if !is_namespace_alias_ident(ctx, object) {
                ctx.push_diagnostic(
                    span.clone(),
                    UnsupportedShape::RuntimeMethodChain,
                    "method call on a value that is not a namespace alias",
                );
            }
        }
        // NonStaticFnArg: any positional argument that is itself an
        // if/else of fn references.
        for a in args {
            if let Expr::If {
                then_block,
                else_branch,
                span,
                ..
            } = &a.value
            {
                if is_dynamic_fn_if(ctx, then_block, else_branch.as_ref()) {
                    ctx.push_diagnostic(
                        span.clone(),
                        UnsupportedShape::NonStaticFnArg,
                        "passing a dynamic fn value as an argument inside a prove block",
                    );
                }
            }
        }
        let _ = call_span; // reserved for future whole-call diagnostics
    }

    walk_expr(ctx, callee);
    for a in args {
        walk_expr(ctx, &a.value);
    }
}
