//! Availability inference — Movimiento 2 Phase 4.
//!
//! Walks the call graph derived from the annotation pass and infers
//! [`Availability`] for every [`CallableKind::UserFn`] in the
//! [`SymbolTable`]. The result tells the VM compiler which functions
//! to skip (ProveIr-only) and the ProveIR compiler which functions
//! to reject (Vm-only), killing gap 1.2.
//!
//! ## Algorithm
//!
//! 1. **Build call graph**: for each `UserFn`, walk its `FnDecl` body
//!    (skipping `Expr::Prove` interiors — those are ProveIR-compiled)
//!    and collect every `SymbolId` the annotation map resolves.
//! 2. **Seed**: functions containing a `prove {}` block → `Vm`.
//! 3. **Propagate** (fixed-point): for each `UserFn`, `meet` its
//!    current availability with every callee's availability. `Both`
//!    narrows to `Vm` or `ProveIr` when a callee is restricted.
//!    Converges in ≤2 passes (lattice height = 2).
//! 4. **Track restrictions**: for each narrowed function, record *why*
//!    it was restricted so the diagnostic pipeline can print
//!    `"foo cannot be used in a prove block because it calls 'print'
//!    (VM-only) via 'bar'"`.

use std::collections::HashMap;

use achronyme_parser::ast::{Block, ElseBranch, Expr, ForIterable, Stmt};

use crate::annotate::{AnnotationKey, ResolvedProgram};
use crate::module_graph::{ModuleGraph, ModuleId};
use crate::symbol::{Availability, CallableKind, SymbolId};
use crate::table::SymbolTable;

// ---- Public types -------------------------------------------------------

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

// ---- Internal: call graph -----------------------------------------------

/// Per-function information collected by the AST walker.
struct FnCallInfo {
    /// Deduplicated set of callee SymbolIds found in this function body.
    direct_calls: Vec<SymbolId>,
    /// Whether the body contains at least one `Expr::Prove`.
    has_prove_block: bool,
}

// ---- Public entry point -------------------------------------------------

/// Infer [`Availability`] for every [`CallableKind::UserFn`] in `table`.
///
/// After this function returns, each `UserFn.availability` is the
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

// ---- Call graph construction --------------------------------------------

fn build_call_graph(
    table: &SymbolTable,
    graph: &ModuleGraph,
    resolved: &ResolvedProgram,
) -> HashMap<SymbolId, FnCallInfo> {
    let mut result = HashMap::new();

    for (sym_id, kind) in table.iter() {
        let (module, stmt_index) = match kind {
            CallableKind::UserFn {
                module, stmt_index, ..
            } => (*module, *stmt_index),
            _ => continue,
        };

        let node = graph.get(module);
        let stmt = match node.program.stmts.get(stmt_index as usize) {
            Some(s) => s,
            None => continue,
        };

        let body = match extract_fn_body(stmt) {
            Some(b) => b,
            None => continue,
        };

        let info = collect_calls_from_body(body, module, &resolved.annotations);
        result.insert(sym_id, info);
    }

    result
}

/// Unwrap `Export { FnDecl { body } }` or `FnDecl { body }` to get the
/// function body. Returns `None` for non-FnDecl statements.
fn extract_fn_body(stmt: &Stmt) -> Option<&Block> {
    match stmt {
        Stmt::Export { inner, .. } => match inner.as_ref() {
            Stmt::FnDecl { body, .. } => Some(body),
            _ => None,
        },
        Stmt::FnDecl { body, .. } => Some(body),
        _ => None,
    }
}

fn collect_calls_from_body(
    body: &Block,
    module: ModuleId,
    annotations: &HashMap<AnnotationKey, SymbolId>,
) -> FnCallInfo {
    let mut info = FnCallInfo {
        direct_calls: Vec::new(),
        has_prove_block: false,
    };
    walk_block(&mut info, body, module, annotations);
    info.direct_calls.sort();
    info.direct_calls.dedup();
    info
}

// ---- AST walker (availability-focused) ----------------------------------

fn walk_block(
    info: &mut FnCallInfo,
    block: &Block,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    for stmt in &block.stmts {
        walk_stmt(info, stmt, module, anns);
    }
}

fn walk_stmt(
    info: &mut FnCallInfo,
    stmt: &Stmt,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    match stmt {
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            walk_expr(info, value, module, anns);
        }
        Stmt::Assignment { target, value, .. } => {
            walk_expr(info, target, module, anns);
            walk_expr(info, value, module, anns);
        }
        Stmt::FnDecl { body, .. } => {
            walk_block(info, body, module, anns);
        }
        Stmt::CircuitDecl { .. } => {
            info.has_prove_block = true;
        }
        Stmt::Print { value, .. } => walk_expr(info, value, module, anns),
        Stmt::Return { value: Some(v), .. } => walk_expr(info, v, module, anns),
        Stmt::Expr(e) => walk_expr(info, e, module, anns),
        Stmt::Export { inner, .. } => walk_stmt(info, inner, module, anns),
        _ => {}
    }
}

fn walk_expr(
    info: &mut FnCallInfo,
    expr: &Expr,
    module: ModuleId,
    anns: &HashMap<AnnotationKey, SymbolId>,
) {
    // Collect annotation if this expression resolved to a known symbol.
    let key = (module, expr.id());
    if let Some(&sym) = anns.get(&key) {
        info.direct_calls.push(sym);
    }

    match expr {
        Expr::Number { .. }
        | Expr::FieldLit { .. }
        | Expr::BigIntLit { .. }
        | Expr::Bool { .. }
        | Expr::StringLit { .. }
        | Expr::Nil { .. }
        | Expr::Ident { .. }
        | Expr::StaticAccess { .. }
        | Expr::Error { .. } => {}

        Expr::BinOp { lhs, rhs, .. } => {
            walk_expr(info, lhs, module, anns);
            walk_expr(info, rhs, module, anns);
        }
        Expr::UnaryOp { operand, .. } => {
            walk_expr(info, operand, module, anns);
        }
        Expr::Call { callee, args, .. } => {
            walk_expr(info, callee, module, anns);
            for arg in args {
                walk_expr(info, &arg.value, module, anns);
            }
        }
        Expr::Index { object, index, .. } => {
            walk_expr(info, object, module, anns);
            walk_expr(info, index, module, anns);
        }
        Expr::DotAccess { object, .. } => {
            walk_expr(info, object, module, anns);
        }
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            walk_expr(info, condition, module, anns);
            walk_block(info, then_block, module, anns);
            match else_branch {
                Some(ElseBranch::Block(b)) => walk_block(info, b, module, anns),
                Some(ElseBranch::If(e)) => walk_expr(info, e, module, anns),
                None => {}
            }
        }
        Expr::For { iterable, body, .. } => {
            match iterable {
                ForIterable::Range { .. } => {}
                ForIterable::ExprRange { end, .. } => walk_expr(info, end, module, anns),
                ForIterable::Expr(e) => walk_expr(info, e, module, anns),
            }
            walk_block(info, body, module, anns);
        }
        Expr::While {
            condition, body, ..
        } => {
            walk_expr(info, condition, module, anns);
            walk_block(info, body, module, anns);
        }
        Expr::Forever { body, .. } => walk_block(info, body, module, anns),
        Expr::Block { block, .. } => walk_block(info, block, module, anns),
        Expr::FnExpr { body, .. } => {
            walk_block(info, body, module, anns);
        }
        Expr::Prove { .. } => {
            // prove {} is a VM expression that produces a proof value.
            // Its inner body is compiled by ProveIR — do NOT walk into it.
            info.has_prove_block = true;
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                walk_expr(info, e, module, anns);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                walk_expr(info, v, module, anns);
            }
        }
    }
}

// ---- Propagation --------------------------------------------------------

/// Lattice meet: narrows availability when a callee is more restricted.
///
/// ```text
///        Both
///       /    \
///     Vm      ProveIr
///       \    /
///       (conflict)
/// ```
fn meet(current: Availability, callee: Availability) -> Availability {
    match (current, callee) {
        (_, Availability::Both) => current,
        (Availability::Both, restricted) => restricted,
        (a, b) if a == b => a,
        // Conflict: Vm meets ProveIr → keep current (first restriction wins).
        _ => current,
    }
}

fn propagate(
    table: &mut SymbolTable,
    call_graph: &HashMap<SymbolId, FnCallInfo>,
) -> AvailabilityResult {
    let mut restrictions: HashMap<SymbolId, RestrictionReason> = HashMap::new();

    // Seed: functions with prove/circuit blocks → Vm
    for (&sym_id, info) in call_graph {
        if info.has_prove_block {
            table.set_user_fn_availability(sym_id, Availability::Vm);
            restrictions.insert(sym_id, RestrictionReason::ContainsProveBlock);
        }
    }

    // Fixed-point: iterate until no availability changes. Converges in
    // ≤2 passes because the lattice has height 2 (Both → Vm/ProveIr).
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
fn user_fn_availability(table: &SymbolTable, id: SymbolId) -> Availability {
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
/// call path like `"foo" → "bar" → "print" (VM-only)`.
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

// ---- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::{BuiltinEntry, BuiltinRegistry, ProveIrLowerHandle, VmFnHandle};
    use crate::module_graph::ModuleId;
    use crate::symbol::Arity;

    /// Build a minimal SymbolTable with some builtins for testing propagation.
    fn test_table() -> SymbolTable {
        let mut reg = BuiltinRegistry::new();
        // 0: poseidon (Both)
        reg.push(BuiltinEntry {
            name: "poseidon",
            arity: Arity::Fixed(2),
            availability: Availability::Both,
            vm_fn: Some(VmFnHandle::PLACEHOLDER),
            prove_ir_lower: Some(ProveIrLowerHandle::PLACEHOLDER),
        });
        // 1: print (Vm)
        reg.push(BuiltinEntry {
            name: "print",
            arity: Arity::Variadic,
            availability: Availability::Vm,
            vm_fn: Some(VmFnHandle::PLACEHOLDER),
            prove_ir_lower: None,
        });
        // 2: range_check (ProveIr)
        reg.push(BuiltinEntry {
            name: "range_check",
            arity: Arity::Fixed(2),
            availability: Availability::ProveIr,
            vm_fn: None,
            prove_ir_lower: Some(ProveIrLowerHandle::PLACEHOLDER),
        });
        let mut table = SymbolTable::with_registry(reg).unwrap();
        // Install builtins as symbols
        table.insert("poseidon", CallableKind::Builtin { entry_index: 0 });
        table.insert("print", CallableKind::Builtin { entry_index: 1 });
        table.insert("range_check", CallableKind::Builtin { entry_index: 2 });
        table
    }

    fn user_fn(table: &mut SymbolTable, name: &str) -> SymbolId {
        table.insert(
            name,
            CallableKind::UserFn {
                qualified_name: name.to_string(),
                module: ModuleId::from_raw(0),
                stmt_index: 0,
                availability: Availability::Both,
            },
        )
    }

    // -- meet tests --

    #[test]
    fn meet_both_with_vm_narrows() {
        assert_eq!(meet(Availability::Both, Availability::Vm), Availability::Vm);
    }

    #[test]
    fn meet_both_with_prove_ir_narrows() {
        assert_eq!(
            meet(Availability::Both, Availability::ProveIr),
            Availability::ProveIr
        );
    }

    #[test]
    fn meet_both_with_both_stays() {
        assert_eq!(
            meet(Availability::Both, Availability::Both),
            Availability::Both
        );
    }

    #[test]
    fn meet_vm_with_vm_stays() {
        assert_eq!(meet(Availability::Vm, Availability::Vm), Availability::Vm);
    }

    #[test]
    fn meet_conflict_keeps_current() {
        assert_eq!(
            meet(Availability::Vm, Availability::ProveIr),
            Availability::Vm
        );
        assert_eq!(
            meet(Availability::ProveIr, Availability::Vm),
            Availability::ProveIr
        );
    }

    // -- propagation tests (no AST, just call graph) --

    #[test]
    fn fn_calling_vm_builtin_becomes_vm() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let print_sym = table.lookup("print").unwrap();

        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![print_sym],
                has_prove_block: false,
            },
        );

        let result = propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Vm);
        assert!(result.restrictions.contains_key(&f));
    }

    #[test]
    fn fn_calling_prove_ir_builtin_becomes_prove_ir() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let rc_sym = table.lookup("range_check").unwrap();

        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![rc_sym],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::ProveIr);
    }

    #[test]
    fn fn_calling_both_builtin_stays_both() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let pos_sym = table.lookup("poseidon").unwrap();

        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![pos_sym],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Both);
    }

    #[test]
    fn fn_with_prove_block_becomes_vm() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");

        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![],
                has_prove_block: true,
            },
        );

        let result = propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Vm);
        assert!(matches!(
            result.restrictions.get(&f),
            Some(RestrictionReason::ContainsProveBlock)
        ));
    }

    #[test]
    fn transitive_propagation_through_user_fn() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let g = user_fn(&mut table, "g");
        let print_sym = table.lookup("print").unwrap();

        // g calls print → Vm. f calls g → Vm transitively.
        let mut cg = HashMap::new();
        cg.insert(
            g,
            FnCallInfo {
                direct_calls: vec![print_sym],
                has_prove_block: false,
            },
        );
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![g],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, g), Availability::Vm);
        assert_eq!(user_fn_availability(&table, f), Availability::Vm);
    }

    #[test]
    fn three_level_chain() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let g = user_fn(&mut table, "g");
        let h = user_fn(&mut table, "h");
        let print_sym = table.lookup("print").unwrap();

        // h → print, g → h, f → g
        let mut cg = HashMap::new();
        cg.insert(
            h,
            FnCallInfo {
                direct_calls: vec![print_sym],
                has_prove_block: false,
            },
        );
        cg.insert(
            g,
            FnCallInfo {
                direct_calls: vec![h],
                has_prove_block: false,
            },
        );
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![g],
                has_prove_block: false,
            },
        );

        let result = propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, h), Availability::Vm);
        assert_eq!(user_fn_availability(&table, g), Availability::Vm);
        assert_eq!(user_fn_availability(&table, f), Availability::Vm);

        // Restriction chain: f → g → h → print
        let chain = restriction_chain(&result, &table, f);
        assert!(chain.len() >= 2, "chain too short: {chain:?}");
    }

    #[test]
    fn unrestricted_fn_stays_both() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let g = user_fn(&mut table, "g");

        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![g],
                has_prove_block: false,
            },
        );
        cg.insert(
            g,
            FnCallInfo {
                direct_calls: vec![],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Both);
        assert_eq!(user_fn_availability(&table, g), Availability::Both);
    }

    #[test]
    fn mutual_recursion_both_stays_both() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let g = user_fn(&mut table, "g");

        // f ↔ g, neither calls anything restricted
        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![g],
                has_prove_block: false,
            },
        );
        cg.insert(
            g,
            FnCallInfo {
                direct_calls: vec![f],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Both);
        assert_eq!(user_fn_availability(&table, g), Availability::Both);
    }

    #[test]
    fn mutual_recursion_with_restriction_propagates() {
        let mut table = test_table();
        let f = user_fn(&mut table, "f");
        let g = user_fn(&mut table, "g");
        let print_sym = table.lookup("print").unwrap();

        // f ↔ g, g also calls print → both become Vm
        let mut cg = HashMap::new();
        cg.insert(
            f,
            FnCallInfo {
                direct_calls: vec![g],
                has_prove_block: false,
            },
        );
        cg.insert(
            g,
            FnCallInfo {
                direct_calls: vec![f, print_sym],
                has_prove_block: false,
            },
        );

        propagate(&mut table, &cg);
        assert_eq!(user_fn_availability(&table, f), Availability::Vm);
        assert_eq!(user_fn_availability(&table, g), Availability::Vm);
    }
}
