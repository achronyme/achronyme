//! Per-module walker state: the `AnnotateCtx` struct that threads
//! through every visitor in [`super::walker`] plus the `LocalKind`
//! enum the context uses to classify let/mut bindings.
//!
//! Kept as its own file so the read-only walker (resolve, classify)
//! can consult the context without pulling in the walker's mutation
//! paths.

use std::collections::HashMap;

use achronyme_parser::ast::Span;

use super::program::AnnotationKey;
use crate::error::{ResolveError, UnsupportedShape};
use crate::module_graph::{ModuleGraph, ModuleNode};
use crate::symbol::SymbolId;
use crate::table::SymbolTable;

/// What flavour of local binding a name represents. Enables Phase
/// 3C.3's FnAlias + prove-block shape diagnostics — the walker stores
/// extra metadata alongside the shadow set so later call sites can
/// re-classify references without re-walking the RHS.
#[derive(Clone, Debug)]
pub(super) enum LocalKind {
    /// Plain value binding: fn params, `for` loop vars, ordinary
    /// `let x = 42`. Shadows module symbols; nothing special.
    Plain,
    /// `let a = p::fn` where the RHS const-resolved at annotation
    /// time to a single fn-valued [`SymbolId`]. Subsequent references
    /// to `a` annotate directly to the target — Phase 3D/3E dispatch
    /// through the target without ever creating a
    /// [`CallableKind::FnAlias`](crate::symbol::CallableKind::FnAlias)
    /// entry in the table (the plan-doc version lives in the table,
    /// but the annotation-map approach gives both backends the same
    /// observable behaviour with no extra mutation cost).
    Alias(SymbolId),
    /// `let a = if c { f } else { g }` where both branches const-
    /// resolve to fn symbols — a dynamic fn value. Calling `a()`
    /// inside a prove block emits
    /// [`UnsupportedShape::DynamicFnValue`].
    DynamicFn,
    /// `let m = { k: v, ... }` — a Map literal. Field/index access
    /// on `m` inside a prove block emits
    /// [`UnsupportedShape::RuntimeMapAccess`].
    RuntimeMap,
}

/// Per-module walker state. Holds read-only refs to the graph/table/
/// module plus `&mut` handles to the annotation map and diagnostic
/// vector, the lexical scope stack, and the prove-block depth
/// counter.
pub(super) struct AnnotateCtx<'a> {
    pub(super) graph: &'a ModuleGraph,
    pub(super) table: &'a SymbolTable,
    pub(super) module: &'a ModuleNode,
    /// Precomputed `"modN::"` prefix (or `""` for the root module) used
    /// to look up the current module's own symbols in [`SymbolTable`].
    pub(super) prefix: String,
    pub(super) annotations: &'a mut HashMap<AnnotationKey, SymbolId>,
    /// Accumulated diagnostics. Phase 3C.3 only pushes
    /// [`ResolveError::ProveBlockUnsupportedShape`] variants; later
    /// phases may add more.
    pub(super) diagnostics: &'a mut Vec<ResolveError>,
    /// Stack of lexical scopes. Each entry binds a name to its
    /// [`LocalKind`]; inner layers shadow outer layers. At module top
    /// level the stack is empty — top-level `let`/`mut` bindings are
    /// not tracked because exported ones live in the `SymbolTable`
    /// and private ones have no annotation-time consumer yet.
    pub(super) scope: Vec<HashMap<String, LocalKind>>,
    /// Depth counter of nested `prove {}` / `circuit {}` blocks. Zero
    /// at module top level; incremented on entry, decremented on
    /// exit. `> 0` means every shape check in the walker should run.
    pub(super) in_prove_depth: u32,
}

impl<'a> AnnotateCtx<'a> {
    pub(super) fn push_scope(&mut self) {
        self.scope.push(HashMap::new());
    }

    pub(super) fn pop_scope(&mut self) {
        self.scope.pop();
    }

    /// Bind a local name to `kind` inside the innermost scope. A
    /// no-op at the module top level (where `scope` is empty) — see
    /// the field docstring above for the rationale.
    pub(super) fn add_local(&mut self, name: &str, kind: LocalKind) {
        if let Some(top) = self.scope.last_mut() {
            top.insert(name.to_string(), kind);
        }
    }

    /// Walk the scope stack from innermost to outermost and return
    /// the first matching binding's kind, if any.
    pub(super) fn lookup_local(&self, name: &str) -> Option<&LocalKind> {
        for layer in self.scope.iter().rev() {
            if let Some(kind) = layer.get(name) {
                return Some(kind);
            }
        }
        None
    }

    pub(super) fn is_local(&self, name: &str) -> bool {
        self.lookup_local(name).is_some()
    }

    pub(super) fn push_diagnostic(
        &mut self,
        span: Span,
        shape: UnsupportedShape,
        reason: &'static str,
    ) {
        self.diagnostics
            .push(ResolveError::ProveBlockUnsupportedShape {
                span,
                shape,
                reason,
            });
    }
}
