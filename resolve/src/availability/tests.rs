use std::collections::HashMap;

use super::propagation::{meet, propagate, user_fn_availability};
use super::{restriction_chain, FnCallInfo, RestrictionReason};
use crate::builtins::{BuiltinEntry, BuiltinRegistry, ProveIrLowerHandle, VmFnHandle};
use crate::module_graph::ModuleId;
use crate::symbol::{Arity, Availability, CallableKind, SymbolId};
use crate::table::SymbolTable;

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

    // g calls print -> Vm. f calls g -> Vm transitively.
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

    // h -> print, g -> h, f -> g
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

    // Restriction chain: f -> g -> h -> print
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

    // f <-> g, neither calls anything restricted
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

    // f <-> g, g also calls print -> both become Vm
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
