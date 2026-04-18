//! Public output types of the resolver pass.
//!
//! Both `AnnotationKey` and `ResolvedProgram` are re-exported at the
//! crate root (`resolve::AnnotationKey`, `resolve::ResolvedProgram`),
//! so any change here has to stay observation-compatible with the two
//! downstream consumers — the VM compiler's Phase 3D shadow dispatch
//! and the ProveIR compiler's Phase 3E annotation-driven resolution.

use std::collections::HashMap;

use achronyme_parser::ast::ExprId;

use crate::error::ResolveError;
use crate::module_graph::ModuleId;
use crate::symbol::SymbolId;

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
