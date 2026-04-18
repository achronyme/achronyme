//! Name-resolution primitives called by the walker:
//! [`resolve_ident`] for bare identifiers, [`resolve_static_access`]
//! for `Type::member`, and [`resolve_dot_access`] for
//! `alias.member`. All three consume an immutable
//! [`AnnotateCtx`](super::context::AnnotateCtx) and return an
//! `Option<SymbolId>`.

use achronyme_parser::ast::Expr;

use super::context::{AnnotateCtx, LocalKind};
use super::helpers::{module_prefix, qualify};
use crate::module_graph::ImportEdgeKind;
use crate::symbol::{CallableKind, SymbolId};

/// Resolve a bare identifier against the walker's lexical stack and the
/// symbol table. Returns `None` on any of:
///
/// - name is a plain local / dynamic-fn local / runtime-map local
///   (shadowing wins; those categories are handled by their own
///   diagnostic paths, not by annotation)
/// - name is not in the current module, not selectively imported, and
///   not a bare builtin
///
/// Returns `Some(target)` when `name` is a
/// [`LocalKind::Alias`](super::context::LocalKind::Alias) — the resolver
/// flattens FnAlias chains at annotation time, so each reference to `a`
/// after `let a = p::fn` is indistinguishable from a direct reference
/// to `p::fn`.
pub(super) fn resolve_ident(ctx: &AnnotateCtx, name: &str) -> Option<SymbolId> {
    if let Some(kind) = ctx.lookup_local(name) {
        return match kind {
            LocalKind::Alias(sid) => Some(*sid),
            LocalKind::Plain | LocalKind::DynamicFn | LocalKind::RuntimeMap => None,
        };
    }

    // 1. Same-module symbol (private fn, exported fn, exported Constant).
    let qualified = qualify(&ctx.prefix, name);
    if let Some(id) = ctx.table.lookup(&qualified) {
        return Some(id);
    }

    // 2. Selective import (`import { foo } from "lib"`).
    for edge in &ctx.module.imports {
        if let ImportEdgeKind::Selective { names } = &edge.kind {
            if names.iter().any(|n| n == name) {
                let target_prefix = module_prefix(edge.target, ctx.graph);
                let target_qualified = qualify(&target_prefix, name);
                if let Some(id) = ctx.table.lookup(&target_qualified) {
                    return Some(id);
                }
            }
        }
    }

    // 3. Bare builtin (requires `register_builtins` to have run).
    //    In the root module this also catches bare lookups that aren't
    //    in the current module's private set — step 1 already tried
    //    the empty-prefix variant, so this is only reached for non-root
    //    modules.
    if !ctx.prefix.is_empty() {
        if let Some(id) = ctx.table.lookup(name) {
            // Only treat as a match if it's actually a builtin — a
            // bare-name hit against some unrelated root-module fn
            // would be a namespace violation.
            if matches!(ctx.table.get(id), CallableKind::Builtin { .. }) {
                return Some(id);
            }
        }
    }

    None
}

/// Resolve `Type::member` syntax. Three possible outcomes:
///
/// 1. The `Type` is a language-level static (`Int`, `Field`, …). The
///    stub [`statics::lookup`](crate::statics::lookup) table is empty
///    in Phase 3C.2, so this branch always falls through — the
///    compilers keep their legacy static matches alive.
/// 2. The `Type` is a namespace import alias. Resolve to the exported
///    name inside the target module.
/// 3. Neither — leave unresolved.
pub(super) fn resolve_static_access(
    ctx: &AnnotateCtx,
    type_name: &str,
    member: &str,
) -> Option<SymbolId> {
    // Language-level statics take precedence but are a stub for now.
    // We explicitly check so a future populated STATIC_MEMBERS table
    // beats namespace-alias collisions.
    if crate::statics::lookup(type_name, member).is_some() {
        // Statics have no SymbolId — they live in a separate table.
        // Signal "handled, but not via SymbolId" by returning None; the
        // compiler's legacy static lookup still runs unchanged.
        return None;
    }

    for edge in &ctx.module.imports {
        if matches!(edge.kind, ImportEdgeKind::Namespace) && edge.alias == type_name {
            let target_prefix = module_prefix(edge.target, ctx.graph);
            let qualified = qualify(&target_prefix, member);
            if let Some(id) = ctx.table.lookup(&qualified) {
                return Some(id);
            }
        }
    }
    None
}

/// Resolve `object.field` where `object` is an identifier that matches a
/// namespace import alias. This is the second parser surface for
/// qualified module access — ProveIR already accepts both `l::foo` and
/// `l.foo` as synonyms, so the resolver treats them uniformly.
pub(super) fn resolve_dot_access(
    ctx: &AnnotateCtx,
    object: &Expr,
    field: &str,
) -> Option<SymbolId> {
    let Expr::Ident { name, .. } = object else {
        return None;
    };
    if ctx.is_local(name) {
        return None;
    }
    for edge in &ctx.module.imports {
        if matches!(edge.kind, ImportEdgeKind::Namespace) && &edge.alias == name {
            let target_prefix = module_prefix(edge.target, ctx.graph);
            let qualified = qualify(&target_prefix, field);
            if let Some(id) = ctx.table.lookup(&qualified) {
                return Some(id);
            }
        }
    }
    None
}
