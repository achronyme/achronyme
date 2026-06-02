use crate::symbol::{Arity, Availability};

use super::*;

fn entry(name: &'static str, availability: Availability, vm: bool, prove: bool) -> BuiltinEntry {
    BuiltinEntry {
        name,
        arity: Arity::Fixed(1),
        availability,
        vm_fn: if vm {
            Some(VmFnHandle::PLACEHOLDER)
        } else {
            None
        },
        prove_ir_lower: if prove {
            Some(ProveIrLowerHandle::PLACEHOLDER)
        } else {
            None
        },
    }
}

#[test]
fn empty_registry_audits_ok() {
    let reg = BuiltinRegistry::new();
    assert!(reg.audit().is_ok());
}

#[test]
fn valid_both_entry_audits_ok() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("poseidon", Availability::Both, true, true));
    assert!(reg.audit().is_ok());
}

#[test]
fn valid_vm_only_entry_audits_ok() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("print", Availability::Vm, true, false));
    assert!(reg.audit().is_ok());
}

#[test]
fn valid_prove_only_entry_audits_ok() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("mux", Availability::ProveIr, false, true));
    assert!(reg.audit().is_ok());
}

#[test]
fn both_missing_vm_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("poseidon", Availability::Both, false, true));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::BothMissingVm { name: "poseidon" })
    );
}

#[test]
fn both_missing_prove_ir_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("poseidon", Availability::Both, true, false));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::BothMissingProveIr { name: "poseidon" })
    );
}

#[test]
fn vm_declaring_prove_ir_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("print", Availability::Vm, true, true));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::VmDeclaresProveIr { name: "print" })
    );
}

#[test]
fn vm_missing_impl_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("print", Availability::Vm, false, false));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::VmMissingImpl { name: "print" })
    );
}

#[test]
fn prove_declaring_vm_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("mux", Availability::ProveIr, true, true));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::ProveIrDeclaresVm { name: "mux" })
    );
}

#[test]
fn prove_missing_impl_is_rejected() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("mux", Availability::ProveIr, false, false));
    assert_eq!(
        reg.audit(),
        Err(BuiltinAuditError::ProveIrMissingImpl { name: "mux" })
    );
}

#[test]
fn realistic_mixed_registry_audits_ok() {
    let mut reg = BuiltinRegistry::new();
    // Both
    reg.push(entry("poseidon", Availability::Both, true, true));
    reg.push(entry("assert_eq", Availability::Both, true, true));
    // Vm only
    reg.push(entry("print", Availability::Vm, true, false));
    reg.push(entry("gc_stats", Availability::Vm, true, false));
    // ProveIr only
    reg.push(entry("mux", Availability::ProveIr, false, true));
    reg.push(entry("range_check", Availability::ProveIr, false, true));
    reg.push(entry("merkle_verify", Availability::ProveIr, false, true));

    assert!(reg.audit().is_ok());
    assert_eq!(reg.len(), 7);
    assert!(reg.lookup("poseidon").is_some());
    assert!(reg.lookup("nonexistent").is_none());
}

#[test]
#[should_panic(expected = "duplicate builtin name")]
fn duplicate_name_panics_on_push() {
    let mut reg = BuiltinRegistry::new();
    reg.push(entry("poseidon", Availability::Both, true, true));
    reg.push(entry("poseidon", Availability::Both, true, true));
}

#[test]
fn audit_error_display() {
    let err = BuiltinAuditError::BothMissingVm { name: "mux" };
    let rendered = format!("{err}");
    assert!(rendered.contains("mux"));
    assert!(rendered.contains("Both"));
    assert!(rendered.contains("vm_fn"));
}

// ─── default() production registry ──────────────────────────────

#[test]
fn default_registry_audits_ok() {
    // The ultimate test: the production registry must pass audit.
    // If this fails, no compilation can proceed — it's the
    // foundational invariant unified dispatch relies on.
    let reg = BuiltinRegistry::default();
    assert!(
        reg.audit().is_ok(),
        "production BuiltinRegistry::default() failed audit"
    );
}

#[test]
fn default_registry_has_21_entries() {
    let reg = BuiltinRegistry::default();
    assert_eq!(
        reg.len(),
        21,
        "expected 21 production builtins, got {}",
        reg.len()
    );
}

#[test]
fn default_registry_availability_counts() {
    let reg = BuiltinRegistry::default();
    let vm_only = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::Vm)
        .count();
    let prove_only = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::ProveIr)
        .count();
    let both = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::Both)
        .count();
    assert_eq!(vm_only, 11, "expected 11 Vm-only builtins");
    assert_eq!(prove_only, 6, "expected 6 ProveIr-only builtins");
    assert_eq!(both, 4, "expected 4 Both builtins");
    assert_eq!(vm_only + prove_only + both, 21);
}

#[test]
fn default_registry_has_expected_both_builtins() {
    let reg = BuiltinRegistry::default();
    for name in ["poseidon", "poseidon_many", "assert", "mux"] {
        let entry = reg
            .lookup(name)
            .unwrap_or_else(|| panic!("missing Both builtin `{name}`"));
        assert_eq!(
            entry.availability,
            Availability::Both,
            "`{name}` should be Both"
        );
        assert!(entry.vm_fn.is_some(), "`{name}` missing vm_fn");
        assert!(
            entry.prove_ir_lower.is_some(),
            "`{name}` missing prove_ir_lower"
        );
    }
}

#[test]
fn default_registry_mux_is_both() {
    // `mux` is registered as `Both`, with a scalar VM fallback in
    // `vm/src/stdlib/core.rs:native_mux`. This lets VM-mode programs
    // import modules that call `mux`.
    let reg = BuiltinRegistry::default();
    let mux = reg.lookup("mux").expect("mux must be registered");
    assert_eq!(mux.availability, Availability::Both);
    assert!(mux.vm_fn.is_some(), "mux must have VM fallback");
    assert!(mux.prove_ir_lower.is_some());
}

#[test]
fn default_registry_vm_handles_are_unique() {
    // Every VM-available builtin should have a unique VmFnHandle
    // (the handle value encodes the positional index).
    let reg = BuiltinRegistry::default();
    let mut seen = std::collections::HashSet::new();
    for entry in reg.entries() {
        if let Some(handle) = entry.vm_fn {
            assert!(
                seen.insert(handle),
                "duplicate VmFnHandle {handle:?} for builtin `{}`",
                entry.name
            );
        }
    }
    // 4 Both + 11 Vm-only = 15 unique vm handles.
    assert_eq!(seen.len(), 15);
}

#[test]
fn default_registry_prove_handles_are_unique() {
    let reg = BuiltinRegistry::default();
    let mut seen = std::collections::HashSet::new();
    for entry in reg.entries() {
        if let Some(handle) = entry.prove_ir_lower {
            assert!(
                seen.insert(handle),
                "duplicate ProveIrLowerHandle {handle:?} for builtin `{}`",
                entry.name
            );
        }
    }
    // 3 Both + 7 ProveIr-only = 10 unique prove handles.
    assert_eq!(seen.len(), 10);
}
