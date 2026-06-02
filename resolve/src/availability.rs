//! Availability inference.
//!
//! Walks the call graph derived from the annotation pass and infers
//! [`Availability`] for every user function in the [`SymbolTable`].
//! The result tells the VM compiler which functions to skip
//! (ProveIr-only) and the ProveIR compiler which functions to reject
//! (Vm-only).
//!
//! ## Algorithm
//!
//! 1. **Build call graph**: for each user function, walk its body
//!    (skipping `Expr::Prove` interiors — those are ProveIR-compiled)
//!    and collect every `SymbolId` the annotation map resolves.
//! 2. **Seed**: functions containing a `prove {}` block become `Vm`.
//! 3. **Propagate** (fixed-point): for each user function, `meet` its
//!    current availability with every callee's availability. `Both`
//!    narrows to `Vm` or `ProveIr` when a callee is restricted.
//! 4. **Track restrictions**: for each narrowed function, record why
//!    it was restricted so diagnostics can render the call chain.

use std::collections::HashMap;

use self::call_graph::build_call_graph;
use self::propagation::propagate;
use crate::annotate::ResolvedProgram;
use crate::module_graph::ModuleGraph;
use crate::symbol::{Availability, SymbolId};
use crate::table::SymbolTable;

mod call_graph;
mod propagation;

pub use propagation::restriction_chain;

#[cfg(test)]
mod tests;

/// Why a function's availability was narrowed from `Both`.
#[derive(Debug, Clone)]
pub enum RestrictionReason {
    /// The function body contains a `prove { }` or `circuit { }` block,
    /// which is a VM-mode expression producing a proof value.
    ContainsProveBlock,
    /// The function directly calls a builtin whose availability does
    /// not include the restricted side.
    CallsBuiltin {
        /// Builtin name (e.g. `"print"`, `"mux"`).
        builtin_name: String,
        /// The builtin's declared availability.
        availability: Availability,
    },
    /// The function calls another user function that is itself restricted.
    CallsRestrictedFn {
        /// Human-readable name of the callee.
        fn_name: String,
        /// SymbolId of the callee (follow to reconstruct the chain).
        fn_symbol: SymbolId,
    },
}

/// Output of [`infer_availability`].
#[derive(Debug, Default)]
pub struct AvailabilityResult {
    /// For every function that was narrowed from `Both`, the reason.
    /// Functions that remain `Both` do not appear here.
    pub restrictions: HashMap<SymbolId, RestrictionReason>,
}

/// Per-function information collected by the AST walker.
struct FnCallInfo {
    /// Deduplicated set of callee SymbolIds found in this function body.
    direct_calls: Vec<SymbolId>,
    /// Whether the body contains at least one `Expr::Prove`.
    has_prove_block: bool,
}

/// Infer [`Availability`] for every user function in `table`.
///
/// After this function returns, each user function availability is the
/// tightest correct value:
/// - `Both` — no restricted constructs anywhere in the call subtree.
/// - `Vm` — transitively calls a VM-only builtin or contains a prove block.
/// - `ProveIr` — transitively calls a ProveIR-only builtin.
pub fn infer_availability(
    table: &mut SymbolTable,
    graph: &ModuleGraph,
    resolved: &ResolvedProgram,
) -> AvailabilityResult {
    let call_graph = build_call_graph(table, graph, resolved);
    propagate(table, &call_graph)
}
