//! Annotate pass — Movimiento 2 Phase 3C.
//!
//! The resolver pass proper: walks every [`ModuleNode`](crate::module_graph::ModuleNode)
//! in a [`ModuleGraph`](crate::module_graph::ModuleGraph) and populates
//! the [`SymbolTable`](crate::table::SymbolTable) with one
//! [`CallableKind::UserFn`](crate::symbol::CallableKind::UserFn) per
//! top-level `fn` declaration and one
//! [`CallableKind::Constant`](crate::symbol::CallableKind::Constant)
//! per exported `let` declaration. The AST itself is then annotated by
//! [`annotate_program`] with a `(ModuleId, ExprId) → SymbolId` side
//! table.
//!
//! ## Public API
//!
//! - [`register_module`] / [`register_all`] / [`register_builtins`] —
//!   Phase 3C.1: populate the [`SymbolTable`](crate::table::SymbolTable)
//!   before the walker runs.
//! - [`annotate_program`] — Phase 3C.2/3C.3: walk every [`Expr`](achronyme_parser::ast::Expr)
//!   in every module and emit the annotation map +
//!   [`ProveBlockUnsupportedShape`](crate::error::ResolveError::ProveBlockUnsupportedShape)
//!   diagnostics.
//! - [`AnnotationKey`] + [`ResolvedProgram`] — the output shape that
//!   Phase 3D/3E consumers read.
//!
//! ## File layout
//!
//! - [`helpers`] — `module_prefix`, `qualify`, `unwrap_exported`,
//!   `is_exported`. Leaf-level utilities used by every other submodule.
//! - [`program`] — public output types + the `annotate_program`
//!   entry that constructs the per-module `AnnotateCtx` and feeds
//!   each module to the walker.
//! - [`register`] — Phase 3C.1 register pass (`register_module`,
//!   `register_all`, `register_builtins`).
//! - [`context`] — `LocalKind` enum + `AnnotateCtx` struct + impl
//!   (push/pop scope, add/lookup local, push diagnostic).
//! - [`resolve`] — name-resolution primitives: `resolve_ident`,
//!   `resolve_static_access`, `resolve_dot_access`. Each returns
//!   `Option<SymbolId>` and consumes an immutable `AnnotateCtx`.
//! - [`classify`] — higher-level helpers built on `resolve`:
//!   `const_resolve_fn`, `classify_let_rhs`, `is_dynamic_fn_if`,
//!   `block_tail_fn`, `is_namespace_alias_ident`. Used by the walker
//!   to label local bindings + emit prove-block shape diagnostics.
//! - [`walker`] — the AST walker proper: `walk_stmt`,
//!   `walk_block_stmts`, `walk_block_scoped`, `walk_expr`, `walk_call`.
//!
//! See `.claude/plans/movimiento-2-unified-dispatch.md` §4 Phase 3 for
//! the original decomposition rationale.

mod classify;
mod context;
mod helpers;
mod program;
mod register;
mod resolve;
mod walker;

pub use program::{annotate_program, AnnotationKey, ResolvedProgram};
pub use register::{register_all, register_builtins, register_module};

#[cfg(test)]
mod tests;
