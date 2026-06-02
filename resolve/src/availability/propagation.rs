use std::collections::HashMap;

use crate::symbol::{Availability, CallableKind, SymbolId};
use crate::table::SymbolTable;

use super::{AvailabilityResult, FnCallInfo, RestrictionReason};

/// Lattice meet: narrows availability when a callee is more restricted.
///
/// ```text
///        Both
///       /    \
///     Vm      ProveIr
///       \    /
///       (conflict)
/// ```
pub(super) fn meet(current: Availability, callee: Availability) -> Availability {
    match (current, callee) {
        (_, Availability::Both) => current,
        (Availability::Both, restricted) => restricted,
        (a, b) if a == b => a,
        // Conflict: Vm meets ProveIr; keep current because first restriction wins.
        _ => current,
    }
}

pub(super) fn propagate(
    table: &mut SymbolTable,
    call_graph: &HashMap<SymbolId, FnCallInfo>,
) -> AvailabilityResult {
    let mut restrictions: HashMap<SymbolId, RestrictionReason> = HashMap::new();

    // Seed: functions with prove/circuit blocks become Vm.
    for (&sym_id, info) in call_graph {
        if info.has_prove_block {
            table.set_user_fn_availability(sym_id, Availability::Vm);
            restrictions.insert(sym_id, RestrictionReason::ContainsProveBlock);
        }
    }

    // Fixed-point: iterate until no availability changes. Converges in
    // at most two passes because the lattice has height two.
    loop {
        let mut changed = false;
        for (&sym_id, info) in call_graph {
            let current = user_fn_availability(table, sym_id);
            let mut new_avail = current;
            let mut new_reason: Option<RestrictionReason> = None;

            for &callee in &info.direct_calls {
                let callee_avail = callee_availability(table, callee);
                let merged = meet(new_avail, callee_avail);
                if merged != new_avail {
                    new_avail = merged;
                    new_reason = Some(build_restriction(table, callee));
                }
            }

            if new_avail != current {
                table.set_user_fn_availability(sym_id, new_avail);
                if let Some(reason) = new_reason {
                    restrictions.insert(sym_id, reason);
                }
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    AvailabilityResult { restrictions }
}

/// Read the current availability of a UserFn symbol.
pub(super) fn user_fn_availability(table: &SymbolTable, id: SymbolId) -> Availability {
    match table.get(id) {
        CallableKind::UserFn { availability, .. } => *availability,
        _ => Availability::Both,
    }
}

/// Determine the availability of a callee (any symbol kind).
fn callee_availability(table: &SymbolTable, callee: SymbolId) -> Availability {
    let resolved = table.resolve_alias(callee).unwrap_or(callee);
    match table.get(resolved) {
        CallableKind::Builtin { entry_index } => table
            .builtin_registry()
            .get(*entry_index)
            .map(|e| e.availability)
            .unwrap_or(Availability::Both),
        CallableKind::UserFn { availability, .. } => *availability,
        CallableKind::CircomTemplate { .. } => Availability::ProveIr,
        CallableKind::Constant { .. } | CallableKind::FnAlias { .. } => Availability::Both,
    }
}

/// Build a [`RestrictionReason`] explaining why a callee restricts its caller.
fn build_restriction(table: &SymbolTable, callee: SymbolId) -> RestrictionReason {
    let resolved = table.resolve_alias(callee).unwrap_or(callee);
    match table.get(resolved) {
        CallableKind::Builtin { entry_index } => {
            let entry = table.builtin_registry().get(*entry_index);
            let (name, avail) = entry
                .map(|e| (e.name.to_string(), e.availability))
                .unwrap_or_else(|| ("?".to_string(), Availability::Both));
            RestrictionReason::CallsBuiltin {
                builtin_name: name,
                availability: avail,
            }
        }
        CallableKind::UserFn { qualified_name, .. } => RestrictionReason::CallsRestrictedFn {
            fn_name: qualified_name.clone(),
            fn_symbol: resolved,
        },
        _ => RestrictionReason::CallsRestrictedFn {
            fn_name: format!("sym#{}", resolved.as_u32()),
            fn_symbol: resolved,
        },
    }
}

/// Walk a [`RestrictionReason`] chain to produce a human-readable
/// call path like `"foo" -> "bar" -> "print" (VM-only)`.
///
/// Used by the diagnostic pipeline to render the "via" chain in error
/// messages. Returns an empty vec if `sym_id` has no restriction.
pub fn restriction_chain(
    result: &AvailabilityResult,
    table: &SymbolTable,
    sym_id: SymbolId,
) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = sym_id;
    let mut seen = std::collections::HashSet::new();

    loop {
        if !seen.insert(current) {
            break;
        }
        match result.restrictions.get(&current) {
            Some(RestrictionReason::ContainsProveBlock) => {
                chain.push(fn_display_name(table, current));
                chain.push("(contains prove block)".to_string());
                break;
            }
            Some(RestrictionReason::CallsBuiltin {
                builtin_name,
                availability,
            }) => {
                chain.push(fn_display_name(table, current));
                chain.push(format!("'{builtin_name}' ({availability}-only)"));
                break;
            }
            Some(RestrictionReason::CallsRestrictedFn { fn_symbol, .. }) => {
                chain.push(fn_display_name(table, current));
                current = *fn_symbol;
            }
            None => break,
        }
    }

    chain
}

fn fn_display_name(table: &SymbolTable, id: SymbolId) -> String {
    match table.get(id) {
        CallableKind::UserFn { qualified_name, .. } => format!("'{qualified_name}'"),
        _ => format!("sym#{}", id.as_u32()),
    }
}
