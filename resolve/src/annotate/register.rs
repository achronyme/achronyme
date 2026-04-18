//! Phase 3C.1 register pass — populate the [`SymbolTable`] with one
//! entry per top-level `fn` / exported `let` / builtin.
//!
//! Runs **before** [`annotate_program`](super::annotate_program) so
//! that per-expression annotation has a live symbol table to query.
//! The three public entries are re-exported at the crate root:
//!
//! - [`register_module`] — single-module variant.
//! - [`register_all`] — convenience over every [`ModuleGraph`] node.
//! - [`register_builtins`] — installs bare names for every
//!   [`BuiltinRegistry`](crate::builtins::BuiltinRegistry) entry.

use std::collections::HashSet;

use achronyme_parser::ast::Stmt;

use super::helpers::{is_exported, module_prefix, qualify, unwrap_exported};
use crate::error::ResolveError;
use crate::module_graph::{ModuleGraph, ModuleId};
use crate::symbol::{Availability, CallableKind, ConstKind};
use crate::table::SymbolTable;

/// Walk every top-level statement in the given module and register
/// every `fn` and (exported) `let` into the table.
///
/// The symbol key is `"{alias}::{name}"` for non-root modules — where
/// `alias` is the *canonical* module identifier, not the per-importer
/// alias — and plain `"{name}"` for the root module. Phase 3E's
/// annotate pass maps per-importer aliases onto these canonical keys.
///
/// ## Key choice
///
/// Phase 3C.1 uses `"modN::{name}"` (where `N = module.as_u32()`) for
/// the non-root prefix because there is no single "canonical alias"
/// yet — a module may be imported under many different aliases across
/// the graph. The key just has to be unique per symbol; 3C.2 overlays
/// a per-importer resolution map on top without needing this key to
/// match anything user-facing.
pub fn register_module(
    table: &mut SymbolTable,
    graph: &ModuleGraph,
    module_id: ModuleId,
) -> Result<(), ResolveError> {
    let node = graph.get(module_id);
    let prefix = module_prefix(module_id, graph);

    // Track which names have been claimed inside this module so we
    // can return `DuplicateModuleSymbol` instead of letting
    // `SymbolTable::insert` panic.
    let mut seen: HashSet<&str> = HashSet::new();

    for (idx, stmt) in node.program.stmts.iter().enumerate() {
        match unwrap_exported(stmt) {
            Some(Stmt::FnDecl { name, .. }) => {
                if !seen.insert(name.as_str()) {
                    return Err(ResolveError::DuplicateModuleSymbol {
                        name: name.clone(),
                        module: module_id.as_u32(),
                    });
                }
                let qualified = qualify(&prefix, name);
                table.insert(
                    qualified.clone(),
                    CallableKind::UserFn {
                        qualified_name: qualified,
                        module: module_id,
                        stmt_index: idx as u32,
                        // Phase 4 availability inference fills this in;
                        // Phase 3C defaults to Both so both compilers
                        // see every fn as a candidate.
                        availability: Availability::Both,
                    },
                );
            }
            Some(Stmt::LetDecl { name, .. }) => {
                if !seen.insert(name.as_str()) {
                    return Err(ResolveError::DuplicateModuleSymbol {
                        name: name.clone(),
                        module: module_id.as_u32(),
                    });
                }
                // Only *exported* lets become module-level
                // `Constant` symbols. Private lets are local to the
                // module body and don't need a SymbolTable entry
                // (Phase 3C.2's per-expression walker handles them
                // via its lexical scope).
                if !is_exported(stmt) {
                    continue;
                }
                let qualified = qualify(&prefix, name);
                table.insert(
                    qualified.clone(),
                    CallableKind::Constant {
                        qualified_name: qualified,
                        // Phase 3C.1 can't infer the const kind without
                        // evaluating the RHS; default to Field and
                        // leave a TODO for Phase 6 when the constant
                        // store lands.
                        const_kind: ConstKind::Field,
                        value_handle: 0,
                    },
                );
            }
            _ => {}
        }
    }

    Ok(())
}

/// Convenience wrapper: register every module in the graph in
/// reverse-topological order (the order [`ModuleGraph::iter_ids`]
/// yields). Dependencies always register before dependents, so a
/// Phase 3C.2 annotate pass can already see its imports in the table
/// by the time it walks its own module.
pub fn register_all(table: &mut SymbolTable, graph: &ModuleGraph) -> Result<(), ResolveError> {
    for id in graph.iter_ids() {
        register_module(table, graph, id)?;
    }
    Ok(())
}

/// Install every builtin in the table's [`BuiltinRegistry`](crate::builtins::BuiltinRegistry)
/// as a [`CallableKind::Builtin`] entry under its bare name.
///
/// Must run **before** [`annotate_program`](super::annotate_program) if
/// the walker is expected to resolve builtin call sites (e.g.
/// `poseidon(a, b)`). Callers that only care about user-module
/// resolution can skip this step —
/// [`annotate_program`](super::annotate_program) simply won't emit
/// annotations for builtin names in that case.
///
/// ## Name-collision policy (Phase 3C.2)
///
/// Builtins go in under their bare name. If a root module also declares
/// `fn poseidon() {...}`, the later [`register_module`] call will panic
/// on duplicate insert. Phase 3C.3+ will refine the shadowing story
/// (either reject user shadowing with a diagnostic or let it win).
/// Until then, the production call order is:
///
/// 1. `register_builtins(&mut table)` — populates bare builtin names.
/// 2. `register_all(&mut table, &graph)` — populates module symbols.
///
/// so any collision surfaces as a clear table panic instead of a silent
/// dispatch mismatch.
pub fn register_builtins(table: &mut SymbolTable) {
    let n = table.builtin_registry().len();
    for i in 0..n {
        // The registry owns `&'static str` names — cheap to clone into
        // the table's `String` key.
        let name = table
            .builtin_registry()
            .get(i)
            .expect("index in 0..len must be valid")
            .name
            .to_string();
        table.insert(name, CallableKind::Builtin { entry_index: i });
    }
}
