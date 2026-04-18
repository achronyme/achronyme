//! Public output types of the resolver pass + the [`annotate_program`]
//! entry point.
//!
//! `AnnotationKey` and `ResolvedProgram` are re-exported at the crate
//! root (`resolve::AnnotationKey`, `resolve::ResolvedProgram`), so any
//! change here has to stay observation-compatible with the two
//! downstream consumers — the VM compiler's Phase 3D shadow dispatch
//! and the ProveIR compiler's Phase 3E annotation-driven resolution.

use std::collections::HashMap;

use achronyme_parser::ast::ExprId;

use super::context::AnnotateCtx;
use super::helpers::module_prefix;
use super::walker::walk_stmt;
use crate::error::ResolveError;
use crate::module_graph::{ModuleGraph, ModuleId};
use crate::symbol::SymbolId;
use crate::table::SymbolTable;

/// Composite key for the annotation map: `(module, expr_id)`.
///
/// [`ExprId`]s are dense *within one parsed [`Program`]*, not across
/// modules — each call to the parser resets its counter to 1. Using
/// the bare `ExprId` as a map key would therefore collide across
/// modules. Phase 3C.2 prefixes with the owning [`ModuleId`] instead,
/// which keeps the resolver pass cheap (no parser-level id remap) and
/// gives Phase 3D/3E consumers an unambiguous handle: they know which
/// module they are compiling, so supplying the pair is free.
pub type AnnotationKey = (ModuleId, ExprId);

/// Output of the resolver pass: the `(ModuleId, ExprId) → SymbolId`
/// annotation map plus any resolve-time diagnostics accumulated along
/// the way.
///
/// The `annotations` table mirrors the plan doc's `ResolvedProgram`
/// sketch: each resolvable leaf in every module gets an entry.
/// Consumers that only care about resolution (Phase 3D/3E compilers)
/// read `annotations`; diagnostic pipelines read `diagnostics` and
/// fold each [`ResolveError`] into the session's error report.
#[derive(Debug, Default, Clone)]
pub struct ResolvedProgram {
    /// `(module, expr_id) → symbol` for every successfully resolved
    /// [`Expr::Ident`](achronyme_parser::ast::Expr::Ident),
    /// [`Expr::StaticAccess`](achronyme_parser::ast::Expr::StaticAccess),
    /// and [`Expr::DotAccess`](achronyme_parser::ast::Expr::DotAccess)
    /// node in every module. Unresolved nodes are silently omitted —
    /// the Phase 3D/3E consumers fall back to their legacy lookup for
    /// anything not in the map.
    pub annotations: HashMap<AnnotationKey, SymbolId>,
    /// Resolve-time diagnostics accumulated by the walker — currently
    /// only [`ResolveError::ProveBlockUnsupportedShape`] variants
    /// emitted inside `prove {}` / `circuit {}` scopes. Empty for
    /// well-formed programs.
    pub diagnostics: Vec<ResolveError>,
    /// Phase 5: `(module, expr_id) → i64` for every expression that
    /// the compile-time const evaluator proved constant. The VM
    /// compiler's circom template dispatcher reads this to accept
    /// `let n = 4; Num2Bits(n)(x)` — not just `Num2Bits(4)(x)`.
    pub const_values: crate::const_eval::ConstValues,
}

/// Walk every [`Expr`](achronyme_parser::ast::Expr) in every module and
/// emit an annotation map from `(ModuleId, ExprId)` to [`SymbolId`] for
/// each resolvable reference.
///
/// This is the resolver pass proper — Phase 3C.2. For every
/// [`Expr::Ident`](achronyme_parser::ast::Expr::Ident),
/// [`Expr::StaticAccess`](achronyme_parser::ast::Expr::StaticAccess), and
/// [`Expr::DotAccess`](achronyme_parser::ast::Expr::DotAccess) the walker
/// tries to resolve the name against:
///
/// 1. the current lexical scope (params + let/mut bindings inside the
///    enclosing function/block) — a match **skips** annotation so
///    Phase 3D/3E's compilers keep using their local-variable storage.
/// 2. the current module's own symbols in the [`SymbolTable`] (private
///    + exported fns registered by [`register_module`](super::register_module)).
/// 3. selective imports (`import { foo } from "lib"`) — the importer's
///    alias is empty, the name must appear in
///    [`ImportEdgeKind::Selective::names`](crate::module_graph::ImportEdgeKind::Selective).
/// 4. namespace imports (`import "lib" as l`) — only reached for
///    [`Expr::StaticAccess`](achronyme_parser::ast::Expr::StaticAccess)
///    and [`Expr::DotAccess`](achronyme_parser::ast::Expr::DotAccess),
///    where the leading `l` is the import alias and the trailing
///    `::foo` / `.foo` is the exported name.
/// 5. builtins — caught by step 2's bare-name lookup if
///    [`register_builtins`](super::register_builtins) ran before this
///    function.
///
/// Unresolvable names are **silently omitted** from the returned map.
/// Phase 3D/3E consumers fall back to their legacy lookup for any
/// `ExprId` not present in the map, so the resolver can ship
/// incrementally without breaking existing behaviour.
///
/// ## What 3C.2 deliberately skips
///
/// - `Expr::Call`'s own annotation. The callee is already walked and
///   annotated; the `Call` node itself doesn't need a separate entry
///   (callers follow the callee's id).
/// - [`FnAlias`](crate::symbol::CallableKind::FnAlias) creation. Phase
///   3C.3 handles `let a = p::fn` const-folding.
/// - [`ProveBlockUnsupportedShape`](crate::error::ResolveError::ProveBlockUnsupportedShape)
///   diagnostics. Phase 3C.3.
/// - Static members (`Int::MAX`, `Field::ZERO`). The
///   [`statics::lookup`](crate::statics::lookup) table is empty until
///   Phase 6; for now we just fall through to the namespace-import
///   check and the compilers keep their legacy static resolution.
/// - `ConstKind` refinement. Phase 3C.1 parks every exported let as
///   `ConstKind::Field`; 3C.2 does not touch that.
/// - Module graph audit. The caller should run [`SymbolTable::audit`]
///   separately after registration + annotation finish.
///
/// ## Gap 2.4 and the definer's scope
///
/// The walker annotates each expression **against the module that
/// declares it**, not the module that eventually inlines it at lowering
/// time. That is the whole point of doing this at parse time: a
/// reference to `hash_node` inside `tree::merkle_step` resolves to
/// `hash::hash_node`'s `SymbolId` now, so by the time the ProveIR
/// compiler inlines `merkle_step` into a `prove {}` block in `main.ach`,
/// there are no bare names left for it to re-resolve against the wrong
/// scope. Phase 3E wires the consumer side; 3C.2 just plants the
/// annotations.
pub fn annotate_program(graph: &ModuleGraph, table: &SymbolTable) -> ResolvedProgram {
    let mut out = ResolvedProgram::default();
    for module in graph.iter() {
        let prefix = module_prefix(module.id, graph);
        let mut ctx = AnnotateCtx {
            graph,
            table,
            module,
            prefix,
            annotations: &mut out.annotations,
            diagnostics: &mut out.diagnostics,
            scope: Vec::new(),
            in_prove_depth: 0,
        };
        for stmt in &module.program.stmts {
            walk_stmt(&mut ctx, stmt);
        }
    }
    out
}
