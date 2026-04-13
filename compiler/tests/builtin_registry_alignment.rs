//! Cross-check that `resolve::BuiltinRegistry::default()` stays aligned
//! with the legacy dispatch surfaces — `vm::specs::NATIVE_TABLE` on the
//! VM side and the `lower_builtin` match arms on the ProveIR side.
//!
//! ## Why this test lives in `compiler/`
//!
//! The `resolve` crate has no deps on `vm` or `ir` (by design — see the
//! dep-direction barrier doc in `resolve/src/builtins.rs`). That means
//! `resolve`'s own tests can only verify the registry is
//! self-consistent. Checking that the registry matches the
//! backend-specific tables has to happen somewhere that sees all three
//! crates. `compiler/` already depends on `vm`, `ir`, and (as of Phase
//! 2A) `resolve` via dev-deps — it's the natural home.
//!
//! ## Phase 2A scope
//!
//! These tests don't assert that dispatch actually flows through the
//! registry — that's Phase 2B / 2C's job. They only verify that the
//! registry is a faithful mirror of the current dispatch surfaces, so
//! later phases can remove the legacy tables with confidence. If this
//! test drifts, the legacy tables and the registry have diverged and
//! Phase 2B would propagate the divergence.

use resolve::builtins::BuiltinRegistry;
use resolve::symbol::{Arity, Availability};
use vm::specs::NATIVE_TABLE;

/// Every entry in `NATIVE_TABLE` must have a matching registry entry
/// with `Availability::Vm` or `Availability::Both`, and with a
/// `VmFnHandle` whose raw index equals the `NATIVE_TABLE` position.
#[test]
fn native_table_aligned_with_registry() {
    let reg = BuiltinRegistry::default();

    for (idx, meta) in NATIVE_TABLE.iter().enumerate() {
        let entry = reg.lookup(meta.name).unwrap_or_else(|| {
            panic!(
                "NATIVE_TABLE[{idx}] = `{}` but registry has no entry \
                 for that name — did you forget to add it to \
                 BuiltinRegistry::default()?",
                meta.name
            )
        });

        assert!(
            entry.availability.includes_vm(),
            "NATIVE_TABLE[{idx}] = `{}` is registered with availability \
             {:?} which does not include Vm — should be Vm or Both",
            meta.name,
            entry.availability,
        );

        let handle = entry.vm_fn.unwrap_or_else(|| {
            panic!(
                "`{}` is VM-available but has no vm_fn handle set",
                meta.name
            )
        });

        assert_eq!(
            handle.as_u32() as usize,
            idx,
            "`{}` has VmFnHandle({}) but NATIVE_TABLE position is {}",
            meta.name,
            handle.as_u32(),
            idx,
        );
    }
}

/// Every VM-available registry entry must have a matching `NATIVE_TABLE`
/// entry at the position given by its `VmFnHandle`. This is the reverse
/// direction of `native_table_aligned_with_registry` — catches the case
/// where the registry has an extra VM entry that's not backed by a real
/// native.
#[test]
fn every_vm_available_registry_entry_backs_a_native() {
    let reg = BuiltinRegistry::default();

    for entry in reg
        .entries()
        .iter()
        .filter(|e| e.availability.includes_vm())
    {
        let handle = entry
            .vm_fn
            .expect("VM-available entry must have vm_fn set (audit should have caught this)");

        let idx = handle.as_u32() as usize;
        let native = NATIVE_TABLE.get(idx).unwrap_or_else(|| {
            panic!(
                "registry entry `{}` has VmFnHandle({}) but NATIVE_TABLE \
                 only has {} entries",
                entry.name,
                idx,
                NATIVE_TABLE.len(),
            )
        });

        assert_eq!(
            native.name, entry.name,
            "NATIVE_TABLE[{idx}] = `{}` but registry entry with that \
             handle is `{}`",
            native.name, entry.name,
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
        "Phase 2C promoted `mux` to Both with a scalar VM fallback. Any \
         new Both additions should also land here and be traceable to a \
         specific phase."
    );
}

/// The ProveIR-only list is the exact set of arms in
/// `ir::prove_ir::compiler::lower_builtin` that are not Both. The
/// hardcoded list below mirrors `.claude/plans/movimiento-2-phase-0-audit.md`
/// §6 minus `mux` (which Phase 2C promoted). If a new ProveIR builtin
/// is added and this test isn't updated, the drift gets caught here.
#[test]
fn production_prove_ir_only_set_matches_extracted_lower_builtin() {
    let reg = BuiltinRegistry::default();
    let mut prove_only: Vec<&str> = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::ProveIr)
        .map(|e| e.name)
        .collect();
    prove_only.sort_unstable();

    // `mux` is deliberately absent — Phase 2C promoted it to Both.
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

/// The VM-only list is the exact set of NATIVE_TABLE entries minus the
/// ones that are Both. Sanity check against the `vm` crate.
#[test]
fn production_vm_only_set_matches_native_table_minus_both() {
    let reg = BuiltinRegistry::default();

    let mut vm_only: Vec<&str> = reg
        .entries()
        .iter()
        .filter(|e| e.availability == Availability::Vm)
        .map(|e| e.name)
        .collect();
    vm_only.sort_unstable();

    let both_names = ["poseidon", "poseidon_many", "assert", "mux"];
    let mut expected: Vec<&str> = NATIVE_TABLE
        .iter()
        .map(|m| m.name)
        .filter(|n| !both_names.contains(n))
        .collect();
    expected.sort_unstable();

    assert_eq!(vm_only, expected);
}

/// Arities on VM-available registry entries must be compatible with
/// the `arity` field stored in NATIVE_TABLE. NATIVE_TABLE uses
/// `isize` with `-1` for variadic; the registry uses `Arity` enum.
/// This test maps one to the other.
#[test]
fn native_table_arities_are_compatible() {
    let reg = BuiltinRegistry::default();

    for meta in NATIVE_TABLE {
        let entry = reg.lookup(meta.name).unwrap();
        match (meta.arity, entry.arity) {
            (-1, Arity::Variadic) => {}
            (-1, other) => panic!(
                "`{}`: NATIVE_TABLE says variadic but registry says {:?}",
                meta.name, other
            ),
            (n, Arity::Fixed(m)) if n >= 0 && n as u8 == m => {}
            (n, Arity::Range(min, max)) if n >= 0 && (n as u8) >= min && (n as u8) <= max => {
                // NATIVE_TABLE arity fits inside the registry's range
            }
            (n, other) => panic!(
                "`{}`: NATIVE_TABLE arity = {} but registry arity = {:?}",
                meta.name, n, other
            ),
        }
    }
}
