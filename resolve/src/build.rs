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

use std::collections::HashMap;

use crate::annotate::{annotate_program, register_all, register_builtins, ResolvedProgram};
use crate::availability::{infer_availability, AvailabilityResult};
use crate::builtins::BuiltinRegistry;
use crate::error::ResolveError;
use crate::module_graph::{ModuleGraph, ModuleId, ModuleSource};
use crate::symbol::{Availability, CallableKind, SymbolId};
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
    /// After Phase 4, every `UserFn` entry has its `availability`
    /// field inferred from the call graph.
    pub table: SymbolTable,
    /// Annotations keyed by `(module_id, expr_id)`.
    pub resolved: ResolvedProgram,
    /// The graph the resolver walked. Kept around because downstream
    /// passes need to map [`ModuleId`] back to paths / imports.
    pub graph: ModuleGraph,
    /// Phase 4 availability inference result — restriction reasons
    /// for every function narrowed from `Both`.
    pub availability: AvailabilityResult,
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
    let availability = infer_availability(&mut table, &graph, &resolved);
    Ok(ResolverState {
        table,
        resolved,
        graph,
        availability,
    })
}

/// Precompute the fn_table dispatch maps from a
/// [`SymbolTable`] + [`ModuleGraph`] for Movimiento 2 Phase 3F/3G.
///
/// Returns `(dispatch_by_symbol, module_by_key)`:
///
/// - `dispatch_by_symbol`: for every [`CallableKind::UserFn`]
///   symbol, the fn_table key the ProveIR compiler actually uses.
///   For root-module fns that's the bare name; for imported-module
///   fns it's `"{alias}::{name}"` where `alias` is the string the
///   importer chose in its `import "./..." as {alias}` statement.
///   This matches the mangling the VM bytecode compiler applies
///   during its recursive `fn_decl_asts` aggregation, so the
///   ProveIR `fn_table` entries lift directly to these keys.
///
/// - `module_by_key`: the inverse lookup the ProveIR
///   `compile_user_fn_call` consults to push the definer's module
///   onto the resolver stack before inlining. Both the annotation
///   path and the legacy StaticAccess path go through this push —
///   gap 2.4 dies here.
///
/// ## Alias derivation
///
/// The alias for each non-root module comes from the
/// [`ImportEdge::alias`](crate::module_graph::ImportEdge) field of
/// the graph edge that imports it. For diamond imports (the same
/// target imported under different aliases by different
/// ancestors), the iteration order of [`ModuleGraph::iter`]
/// determines last-write-wins — consistent with how the VM
/// compiler's `fn_decl_asts` handles the same case today, so no
/// new divergence.
///
/// Selective imports (`import { a, b } from "./x"`) have an empty
/// `alias` string in their edge; their [`CallableKind::UserFn`]
/// entries are skipped (they'd use bare names that collide with
/// the root). Phase 3F/3G's scope is namespace imports only;
/// selective-import symbols fall through to legacy dispatch
/// unchanged.
///
/// ## Layering
///
/// This function lives in `resolve` because its inputs and
/// outputs are entirely resolver types (SymbolTable, ModuleGraph,
/// SymbolId, String). The "convention" it encodes — that
/// non-root fn_table keys are `{alias}::{name}` — is a property
/// of the resolver's naming model, not a compiler-specific hack.
/// Both the VM bytecode compiler and the ProveIR compiler call
/// this same helper.
pub fn build_dispatch_maps(
    table: &SymbolTable,
    graph: &ModuleGraph,
) -> (HashMap<SymbolId, String>, HashMap<String, ModuleId>) {
    // Pass 1: derive ModuleId → alias by walking every namespace
    // import edge. Empty aliases (selective imports) are skipped.
    let mut alias_for_module: HashMap<ModuleId, String> = HashMap::new();
    for module in graph.iter() {
        for edge in &module.imports {
            if !edge.alias.is_empty() {
                alias_for_module.insert(edge.target, edge.alias.clone());
            }
        }
    }

    // Pass 2: for every UserFn symbol, compute its fn_table key.
    // Entries whose owning module has no alias (selective-only
    // imports, or pure-root modules) are omitted — dispatch for
    // them falls through to the legacy name-based path.
    let mut by_symbol: HashMap<SymbolId, String> = HashMap::new();
    let mut by_key: HashMap<String, ModuleId> = HashMap::new();
    let root_module = graph.root();
    for (sid, kind) in table.iter() {
        let (qualified_name, module) = match kind {
            CallableKind::UserFn {
                qualified_name,
                module,
                ..
            } => (qualified_name, *module),
            _ => continue,
        };
        // The resolver's qualified_name is either the bare name
        // (root module) or `"mod{N}::name"` (non-root). We extract
        // the trailing bare identifier; for root fns the rsplit
        // returns the whole string, which is exactly what we want.
        let bare = qualified_name.rsplit("::").next().unwrap_or(qualified_name);
        let key = if module == root_module {
            bare.to_string()
        } else {
            match alias_for_module.get(&module) {
                Some(alias) => format!("{alias}::{bare}"),
                None => continue,
            }
        };
        by_symbol.insert(sid, key.clone());
        by_key.insert(key, module);
    }

    (by_symbol, by_key)
}

/// Build a map from fn_table key → [`Availability`] for every
/// [`CallableKind::UserFn`] that has a dispatch key.
///
/// The VM compiler uses this to skip bytecode emission for
/// `ProveIr`-only functions and to check availability before
/// compiling function bodies. Runs after [`infer_availability`]
/// has narrowed the table entries.
///
/// Keys use the same `{alias}::{name}` convention as
/// [`build_dispatch_maps`].
pub fn build_availability_map(
    table: &SymbolTable,
    graph: &ModuleGraph,
) -> HashMap<String, Availability> {
    let mut alias_for_module: HashMap<ModuleId, String> = HashMap::new();
    for module in graph.iter() {
        for edge in &module.imports {
            if !edge.alias.is_empty() {
                alias_for_module.insert(edge.target, edge.alias.clone());
            }
        }
    }

    let mut result = HashMap::new();
    let root_module = graph.root();
    for (_sid, kind) in table.iter() {
        let (qualified_name, module, availability) = match kind {
            CallableKind::UserFn {
                qualified_name,
                module,
                availability,
                ..
            } => (qualified_name, *module, *availability),
            _ => continue,
        };
        let bare = qualified_name.rsplit("::").next().unwrap_or(qualified_name);
        let key = if module == root_module {
            bare.to_string()
        } else {
            match alias_for_module.get(&module) {
                Some(alias) => format!("{alias}::{bare}"),
                None => continue,
            }
        };
        result.insert(key, availability);
    }
    result
}
