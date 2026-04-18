//! Higher-level classification helpers built on top of `resolve`:
//!
//! - [`const_resolve_fn`] — narrow a `let` RHS to a fn-valued
//!   `SymbolId` (the structural pattern behind `LocalKind::Alias`).
//! - [`classify_let_rhs`] — pick the right `LocalKind` for a `let`
//!   binding based on its RHS shape.
//! - [`is_dynamic_fn_if`] — detect the `if/else { f } { g }`
//!   structure that produces `LocalKind::DynamicFn`.
//! - [`block_tail_fn`] — extract the fn-valued symbol from a block's
//!   tail expression.
//! - [`is_namespace_alias_ident`] — distinguish `alias.foo()` (valid
//!   namespace call) from `value.method()` (runtime dispatch) when
//!   the walker is checking prove-block shape.
//!
//! All five are `pub(super)`. The walker calls them while making
//! `add_local` and prove-block diagnostic decisions.

use achronyme_parser::ast::{Block, ElseBranch, Expr, Stmt};

use super::context::{AnnotateCtx, LocalKind};
use super::resolve::{resolve_dot_access, resolve_ident, resolve_static_access};
use crate::module_graph::ImportEdgeKind;
use crate::symbol::{CallableKind, SymbolId};

/// Try to const-resolve a `let` RHS to a single fn-valued [`SymbolId`].
/// Only the three leaf shapes (bare ident, `Type::member`, `alias.member`)
/// are considered — matching a more elaborate expression dynamically
/// is the user's job (or the VM's). Returns `Some(id)` when:
///
/// - the expression is [`Expr::Ident`] / [`Expr::StaticAccess`] /
///   [`Expr::DotAccess`] and resolves against the current context;
/// - AND the resolved symbol's kind is [`CallableKind::UserFn`],
///   [`CallableKind::Builtin`], or [`CallableKind::FnAlias`]
///   (constants and circom templates aren't first-class callables in
///   the 3C.3 alias sense).
pub(super) fn const_resolve_fn(ctx: &AnnotateCtx, expr: &Expr) -> Option<SymbolId> {
    let sid = match expr {
        Expr::Ident { name, .. } => resolve_ident(ctx, name)?,
        Expr::StaticAccess {
            type_name, member, ..
        } => resolve_static_access(ctx, type_name, member)?,
        Expr::DotAccess { object, field, .. } => resolve_dot_access(ctx, object, field)?,
        _ => return None,
    };
    match ctx.table.get(sid) {
        CallableKind::UserFn { .. }
        | CallableKind::Builtin { .. }
        | CallableKind::FnAlias { .. } => Some(sid),
        _ => None,
    }
}

/// Decide what [`LocalKind`] a `let x = <rhs>` binding should produce.
/// The classification drives Phase 3C.3's FnAlias + shape diagnostics:
///
/// - a const-resolved fn reference → [`LocalKind::Alias`]
/// - an `if` whose both branches const-resolve to fn references →
///   [`LocalKind::DynamicFn`]
/// - a map literal → [`LocalKind::RuntimeMap`]
/// - anything else → [`LocalKind::Plain`]
pub(super) fn classify_let_rhs(ctx: &AnnotateCtx, rhs: &Expr) -> LocalKind {
    if let Some(target) = const_resolve_fn(ctx, rhs) {
        return LocalKind::Alias(target);
    }
    if let Expr::If {
        then_block,
        else_branch,
        ..
    } = rhs
    {
        if is_dynamic_fn_if(ctx, then_block, else_branch.as_ref()) {
            return LocalKind::DynamicFn;
        }
    }
    if matches!(rhs, Expr::Map { .. }) {
        return LocalKind::RuntimeMap;
    }
    LocalKind::Plain
}

/// Return `true` if both branches of an `if/else` const-resolve to
/// fn-valued symbols — the structural pattern that makes a binding a
/// [`LocalKind::DynamicFn`] and that triggers
/// [`UnsupportedShape::DynamicFnValue`](crate::error::UnsupportedShape::DynamicFnValue) /
/// [`UnsupportedShape::NonStaticFnArg`](crate::error::UnsupportedShape::NonStaticFnArg)
/// inside a prove block. The tail of each branch is checked: the
/// last statement of a block must be a `Stmt::Expr` that
/// const-resolves, or the else branch must chain to another `if` that
/// itself is a dynamic-fn `if`.
pub(super) fn is_dynamic_fn_if(
    ctx: &AnnotateCtx,
    then_block: &Block,
    else_branch: Option<&ElseBranch>,
) -> bool {
    if block_tail_fn(ctx, then_block).is_none() {
        return false;
    }
    match else_branch {
        Some(ElseBranch::Block(b)) => block_tail_fn(ctx, b).is_some(),
        Some(ElseBranch::If(e)) => {
            // Nested else-if: require the whole chain to be fn-valued.
            if let Expr::If {
                then_block: inner_then,
                else_branch: inner_else,
                ..
            } = e.as_ref()
            {
                is_dynamic_fn_if(ctx, inner_then, inner_else.as_ref())
            } else {
                false
            }
        }
        None => false,
    }
}

/// Extract the fn-valued symbol out of a block's tail statement, if any.
pub(super) fn block_tail_fn(ctx: &AnnotateCtx, block: &Block) -> Option<SymbolId> {
    match block.stmts.last()? {
        Stmt::Expr(e) => const_resolve_fn(ctx, e),
        _ => None,
    }
}

/// Return `true` if the given expression is an [`Expr::Ident`] whose
/// name matches a namespace import alias on the current module. Used
/// by the prove-block method-chain diagnostic to distinguish
/// `l.foo()` (valid namespace call) from `value.method()` (runtime
/// method dispatch).
pub(super) fn is_namespace_alias_ident(ctx: &AnnotateCtx, expr: &Expr) -> bool {
    let Expr::Ident { name, .. } = expr else {
        return false;
    };
    if ctx.is_local(name) {
        return false;
    }
    ctx.module
        .imports
        .iter()
        .any(|e| matches!(e.kind, ImportEdgeKind::Namespace) && &e.alias == name)
}
