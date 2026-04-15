//! Shared resolver-state construction — Movimiento 2 Phase 3E.
//!
//! Both the VM bytecode compiler and the ProveIR compiler need to
//! build a [`ModuleGraph`] → [`SymbolTable`] → [`ResolvedProgram`]
//! chain for the same program. Before Phase 3E each backend grew its
//! own ad-hoc copy of that sequence (see
//! `compiler::Compiler::try_auto_build_resolver_state`); this module
//! is the single entry point they both call now.
//!
//! The helper is intentionally thin — it owns the call order
//! (`register_builtins` → `register_all` → `annotate_program`) and
//! nothing else. Everything upstream (which [`ModuleSource`] adapter,
//! which root path, whether to even build a resolver state at all) is
//! still the caller's call.
//!
//! ## Why a struct instead of a tuple
//!
//! Callers historically stored the three outputs as separate
//! `Option<T>` fields (see Phase 3D's [`Compiler`] in the compiler
//! crate). A struct makes the install-vs-build split explicit:
//! [`ResolverState`] is the "built" shape; the compiler destructures
//! it into its own fields at install time.

use crate::annotate::{annotate_program, register_all, register_builtins, ResolvedProgram};
use crate::builtins::BuiltinRegistry;
use crate::error::ResolveError;
use crate::module_graph::{ModuleGraph, ModuleId, ModuleSource};
use crate::table::SymbolTable;

/// The three pieces of state the resolver produces for a program.
///
/// Build with [`build_resolver_state`]; destructure into a compiler's
/// own fields at install time. Cheap-ish to build (one graph build +
/// one symbol-table pass + one annotation walk) but not free —
/// callers that embed a resolver state per-prove-block should consider
/// sharing via `Arc` or building once per compile.
pub struct ResolverState {
    /// Flat symbol table indexed by [`SymbolId`](crate::symbol::SymbolId).
    pub table: SymbolTable,
    /// Annotations keyed by `(module_id, expr_id)`.
    pub resolved: ResolvedProgram,
    /// The graph the resolver walked. Kept around because downstream
    /// passes need to map [`ModuleId`] back to paths / imports.
    pub graph: ModuleGraph,
}

impl ResolverState {
    /// Convenience accessor for the root [`ModuleId`].
    pub fn root(&self) -> ModuleId {
        self.graph.root()
    }
}

/// Build a [`ResolverState`] for `root_relative_path` using `source`.
///
/// Owns the canonical call order shared between the VM compiler's
/// auto-build path and the ProveIR compiler's standalone path:
///
/// 1. [`ModuleGraph::build`] walks the import graph.
/// 2. A fresh [`SymbolTable`] is created from the default
///    [`BuiltinRegistry`].
/// 3. [`register_builtins`] installs every builtin.
/// 4. [`register_all`] installs every module's exported symbols.
/// 5. [`annotate_program`] walks every module and fills the
///    annotation map.
///
/// Any of those steps can fail and the error is propagated — Phase 3E
/// callers that want to run in shadow mode (observation only) should
/// swallow the error at the call site, not inside this helper.
pub fn build_resolver_state(
    root_relative_path: &str,
    source: &mut dyn ModuleSource,
) -> Result<ResolverState, ResolveError> {
    let graph = ModuleGraph::build(root_relative_path, source)?;
    let mut table = SymbolTable::with_registry(BuiltinRegistry::default())?;
    register_builtins(&mut table);
    register_all(&mut table, &graph)?;
    let resolved = annotate_program(&graph, &table);
    Ok(ResolverState {
        table,
        resolved,
        graph,
    })
}
