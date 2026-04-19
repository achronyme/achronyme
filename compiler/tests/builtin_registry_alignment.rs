//! Verify that `resolve::BuiltinRegistry::default()` is correctly wired
//! to both the VM runtime and the ProveIR dispatch table.
//!
//! ## Why this test lives in `compiler/`
//!
//! The `resolve` crate has no deps on `vm` or `ir` (by design — see the
//! dep-direction barrier doc in `resolve/src/builtins.rs`). That means
//! `resolve`'s own tests can only verify the registry is
//! self-consistent. Checking that the registry matches the actual
//! runtime natives requires a crate that sees all three crates.
//! `compiler/` depends on `vm`, `ir`, and `resolve` — it's the natural
//! home.
//!
//! ## Phase 6 scope
//!
//! After Phase 6, the registry IS the dispatch surface. These tests
//! verify:
//! - Every VM-available registry entry is backed by a real native from
//!   `builtin_modules()`.
//! - Every ProveIR-available registry entry has a valid
//!   `ProveIrLowerHandle` within the dispatch table bounds.
//! - The production availability sets are frozen (Both, Vm-only,
//!   ProveIr-only) so additions are explicit.

use resolve::builtins::BuiltinRegistry;
use resolve::symbol::Availability;

/// Every VM-available registry entry must be backed by a real native
/// from `builtin_modules()`, at the position given by its `VmFnHandle`.
#[test]
fn every_vm_registry_entry_has_a_real_native() {
    let reg = BuiltinRegistry::default();
    let vm_entries = reg.vm_entries_by_handle();

    let modules = akron::module::builtin_modules();
    let mut all_defs = Vec::new();
    for module in &modules {
        all_defs.extend(module.natives());
    }

    assert_eq!(
        vm_entries.len(),
        all_defs.len(),
        "registry VM entries ({}) != builtin_modules definitions ({})",
        vm_entries.len(),
        all_defs.len(),
    );

    for (i, (entry, def)) in vm_entries.iter().zip(all_defs.iter()).enumerate() {
        assert_eq!(
            entry.name, def.name,
            "Position {i}: registry says '{}' but builtin_modules says '{}'",
            entry.name, def.name,
        );
        let handle = entry.vm_fn.expect("vm_entries_by_handle guarantees vm_fn");
        assert_eq!(
            handle.as_u32() as usize,
            i,
            "'{}' has VmFnHandle({}) but expected position {}",
            entry.name,
            handle.as_u32(),
            i,
        );
    }
}

/// Every ProveIR-available registry entry must have a valid
/// `ProveIrLowerHandle` within the dispatch table bounds (0..10).
#[test]
fn every_prove_ir_registry_entry_has_a_valid_handle() {
    let reg = BuiltinRegistry::default();
    let prove_count = reg.prove_ir_count();

    for entry in reg
        .entries()
        .iter()
        .filter(|e| e.availability.includes_prove_ir())
    {
        let handle = entry.prove_ir_lower.unwrap_or_else(|| {
            panic!(
                "`{}` is ProveIr-available but has no prove_ir_lower",
                entry.name
            )
        });
        assert!(
            (handle.as_u32() as usize) < prove_count,
            "`{}` has ProveIrLowerHandle({}) but only {} ProveIR builtins exist",
            entry.name,
            handle.as_u32(),
            prove_count,
        );
    }
}

/// The Both entries are the overlap between VM and ProveIR. They must
/// have both handles populated — the registry audit enforces this but
/// we assert specifically on the production set so a regression here
/// is immediately attributable to the `Both` list.
#[test]
fn production_both_set_is_complete() {
    let reg = BuiltinRegistry::default();
    let both: Vec<&str> = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::Both)
        .map(|e| e.name)
        .collect();
    assert_eq!(
        both,
        vec!["poseidon", "poseidon_many", "assert", "mux"],
        "Any new Both additions should land here and be traceable to a \
         specific phase."
    );
}

/// The ProveIR-only set. If a new ProveIR builtin is added and this
/// test isn't updated, the drift gets caught here.
#[test]
fn production_prove_ir_only_set() {
    let reg = BuiltinRegistry::default();
    let mut prove_only: Vec<&str> = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::ProveIr)
        .map(|e| e.name)
        .collect();
    prove_only.sort_unstable();

    let mut expected = [
        "range_check",
        "merkle_verify",
        "len",
        "assert_eq",
        "int_div",
        "int_mod",
    ];
    expected.sort_unstable();

    assert_eq!(
        prove_only, expected,
        "ProveIr-only builtin set drift — update BuiltinRegistry::default() \
         or this test when adding / removing a ProveIR builtin"
    );
}

/// The VM-only set. Pinned so additions are explicit.
#[test]
fn production_vm_only_set() {
    let reg = BuiltinRegistry::default();

    let mut vm_only: Vec<&str> = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::Vm)
        .map(|e| e.name)
        .collect();
    vm_only.sort_unstable();

    let mut expected = vec![
        "print",
        "typeof",
        "time",
        "proof_json",
        "proof_public",
        "proof_vkey",
        "verify_proof",
        "gc_stats",
        "bigint256",
        "bigint512",
        "from_bits",
    ];
    expected.sort_unstable();

    assert_eq!(vm_only, expected);
}

/// Registry arities for VM-available entries must be compatible with
/// what `builtin_modules()` declares. The VM uses `isize` with `-1`
/// for variadic; the registry uses `Arity` enum.
#[test]
fn vm_arities_are_compatible() {
    use resolve::symbol::Arity;

    let reg = BuiltinRegistry::default();
    let vm_entries = reg.vm_entries_by_handle();

    let modules = akron::module::builtin_modules();
    let mut all_defs = Vec::new();
    for module in &modules {
        all_defs.extend(module.natives());
    }

    for (entry, def) in vm_entries.iter().zip(all_defs.iter()) {
        match (def.arity, entry.arity) {
            (-1, Arity::Variadic) => {}
            (-1, other) => panic!(
                "`{}`: module says variadic but registry says {:?}",
                entry.name, other
            ),
            (n, Arity::Fixed(m)) if n >= 0 && n as u8 == m => {}
            (n, Arity::Range(min, max)) if n >= 0 && (n as u8) >= min && (n as u8) <= max => {}
            (n, other) => panic!(
                "`{}`: module arity = {} but registry arity = {:?}",
                entry.name, n, other
            ),
        }
    }
}
