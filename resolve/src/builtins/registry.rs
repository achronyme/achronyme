use crate::symbol::{Arity, Availability};

use super::{BuiltinAuditError, BuiltinEntry, ProveIrLowerHandle, VmFnHandle};

/// The set of all registered builtins in a compilation session.
///
/// [`BuiltinRegistry::default()`] returns the production registry
/// populated with every builtin shipped by Achronyme. Both compilers
/// dispatch through this registry — it is the single source of truth.
///
/// Fields are **private** to protect the uniqueness invariant maintained
/// by [`BuiltinRegistry::push`]. Use [`BuiltinRegistry::entries`],
/// [`BuiltinRegistry::len`], [`BuiltinRegistry::lookup`], etc. for read
/// access.
#[derive(Debug, Clone)]
pub struct BuiltinRegistry {
    /// The entries in declaration order. The order is NOT significant
    /// to dispatch (we use `name` as the key) but is preserved for
    /// stable diagnostic output.
    entries: Vec<BuiltinEntry>,
}

/// Convenience for building a [`BuiltinEntry`] inline in
/// [`BuiltinRegistry::default()`].
macro_rules! entry {
    (vm $name:literal, $arity:expr, vm = $vm_idx:literal) => {
        BuiltinEntry {
            name: $name,
            arity: $arity,
            availability: Availability::Vm,
            vm_fn: Some(VmFnHandle($vm_idx)),
            prove_ir_lower: None,
        }
    };
    (prove $name:literal, $arity:expr, prove = $prove_idx:literal) => {
        BuiltinEntry {
            name: $name,
            arity: $arity,
            availability: Availability::ProveIr,
            vm_fn: None,
            prove_ir_lower: Some(ProveIrLowerHandle($prove_idx)),
        }
    };
    (both $name:literal, $arity:expr, vm = $vm_idx:literal, prove = $prove_idx:literal) => {
        BuiltinEntry {
            name: $name,
            arity: $arity,
            availability: Availability::Both,
            vm_fn: Some(VmFnHandle($vm_idx)),
            prove_ir_lower: Some(ProveIrLowerHandle($prove_idx)),
        }
    };
}

impl Default for BuiltinRegistry {
    /// Production registry with every builtin Achronyme ships.
    ///
    /// ## Handle conventions
    ///
    /// - `VmFnHandle(n)` — `n` is the builtin's positional index in
    ///   the VM's `builtin_modules()` registration order. The
    ///   integration test `compiler/tests/builtin_registry_alignment.rs`
    ///   verifies alignment on every CI run.
    /// - `ProveIrLowerHandle(n)` — `n` is the slot in the ProveIR
    ///   dispatch table (`dispatch_builtin_by_handle` in
    ///   `ir_forge::compiler`).
    ///
    /// ## Inventory
    ///
    /// - **4 Both**: `poseidon`, `poseidon_many`, `assert`, `mux`
    ///   (`mux` is dispatched in both backends with a scalar VM fallback)
    /// - **11 Vm-only**: `print`, `typeof`, `time`, `proof_json`,
    ///   `proof_public`, `proof_vkey`, `verify_proof`, `gc_stats`,
    ///   `bigint256`, `bigint512`, `from_bits`
    /// - **6 ProveIr-only**: `range_check`, `merkle_verify`, `len`,
    ///   `assert_eq`, `int_div`, `int_mod`
    ///
    /// Total: **21 builtins**.
    fn default() -> Self {
        let entries = vec![
            // ── VM-only (11) ───────────────────────────────────────
            // VmFnHandle = positional index in builtin_modules()
            entry!(vm "print",         Arity::Variadic,   vm = 0),
            entry!(vm "typeof",        Arity::Fixed(1),   vm = 1),
            // Handle 2 is `assert` — registered as Both below.
            entry!(vm "time",          Arity::Fixed(0),   vm = 3),
            entry!(vm "proof_json",    Arity::Fixed(1),   vm = 4),
            entry!(vm "proof_public",  Arity::Fixed(1),   vm = 5),
            entry!(vm "proof_vkey",    Arity::Fixed(1),   vm = 6),
            // Handles 7-8 (poseidon, poseidon_many) are Both — below.
            entry!(vm "verify_proof",  Arity::Fixed(1),   vm = 9),
            entry!(vm "gc_stats",      Arity::Fixed(0),   vm = 10),
            // Handle 11 is `mux` — Both, below.
            entry!(vm "bigint256",     Arity::Fixed(1),   vm = 12),
            entry!(vm "bigint512",     Arity::Fixed(1),   vm = 13),
            entry!(vm "from_bits",     Arity::Fixed(2),   vm = 14),
            // ── Both (4) ───────────────────────────────────────────
            entry!(both "poseidon",      Arity::Fixed(2), vm = 7,  prove = 0),
            entry!(both "poseidon_many", Arity::Variadic, vm = 8,  prove = 1),
            entry!(both "assert",        Arity::Fixed(1), vm = 2,  prove = 7),
            entry!(both "mux",           Arity::Fixed(3), vm = 11, prove = 2),
            // ── ProveIR-only (6) ───────────────────────────────────
            // ProveIrLowerHandle = slot in dispatch_builtin_by_handle.
            entry!(prove "range_check",   Arity::Fixed(2),    prove = 3),
            entry!(prove "merkle_verify", Arity::Fixed(4),    prove = 4),
            entry!(prove "len",           Arity::Fixed(1),    prove = 5),
            entry!(prove "assert_eq",     Arity::Range(2, 3), prove = 6),
            entry!(prove "int_div",       Arity::Fixed(3),    prove = 8),
            entry!(prove "int_mod",       Arity::Fixed(3),    prove = 9),
        ];

        let registry = Self { entries };

        // Fail fast if the hand-written entries violate any audit
        // invariant. This runs once per process, not per dispatch.
        registry
            .audit()
            .expect("BuiltinRegistry::default() failed audit — production registry is malformed");

        registry
    }
}

impl BuiltinRegistry {
    /// Create an empty registry. Useful for tests; production code should
    /// use [`BuiltinRegistry::default()`] which returns the populated
    /// production registry.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a single entry. Panics if a builtin with the same `name`
    /// already exists — name collisions are a build-time bug, not a
    /// recoverable error.
    pub fn push(&mut self, entry: BuiltinEntry) {
        if self.entries.iter().any(|e| e.name == entry.name) {
            panic!(
                "BuiltinRegistry: duplicate builtin name `{}` — every \
                 registry entry must have a unique name",
                entry.name
            );
        }
        self.entries.push(entry);
    }

    /// Read-only view of the entries in declaration order. Callers that
    /// only need random access by index should use
    /// [`BuiltinRegistry::get`] instead; this slice is exposed for
    /// iteration and diagnostic purposes.
    pub fn entries(&self) -> &[BuiltinEntry] {
        &self.entries
    }

    /// How many entries are in the registry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the registry empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a builtin by name. Linear scan, but there are ~23 entries
    /// and the resolver pass consults this at most once per call site.
    /// Convenience wrapper over [`BuiltinRegistry::lookup_index`] +
    /// [`BuiltinRegistry::get`].
    pub fn lookup(&self, name: &str) -> Option<&BuiltinEntry> {
        self.lookup_index(name).and_then(|i| self.get(i))
    }

    /// Look up a builtin by name and return its index in the registry.
    ///
    /// This is the index [`CallableKind::Builtin::entry_index`] stores;
    /// the resolver pass calls this to construct
    /// [`CallableKind::Builtin`] entries without a second lookup hop.
    ///
    /// [`CallableKind::Builtin`]: crate::symbol::CallableKind::Builtin
    /// [`CallableKind::Builtin::entry_index`]: crate::symbol::CallableKind::Builtin
    pub fn lookup_index(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    /// Random-access by index. The index must come from
    /// [`BuiltinRegistry::lookup_index`] or from a previously-stored
    /// [`CallableKind::Builtin::entry_index`].
    ///
    /// [`CallableKind::Builtin::entry_index`]: crate::symbol::CallableKind::Builtin
    pub fn get(&self, index: usize) -> Option<&BuiltinEntry> {
        self.entries.get(index)
    }

    /// Number of VM-available entries (both `Vm` and `Both`).
    ///
    /// This replaces the old `akron::specs::NATIVE_COUNT` constant — the
    /// registry is now the single source of truth for how many native
    /// slots the VM must reserve.
    pub fn vm_native_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.availability.includes_vm())
            .count()
    }

    /// VM-available entries sorted by [`VmFnHandle`] order.
    ///
    /// The compiler uses this to populate `global_symbols` in the
    /// correct positional order, and the VM uses it to validate that
    /// `builtin_modules()` produces natives in the same order.
    pub fn vm_entries_by_handle(&self) -> Vec<&BuiltinEntry> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.availability.includes_vm())
            .collect();
        entries.sort_by_key(|e| e.vm_fn.map_or(u32::MAX, |h| h.as_u32()));
        entries
    }

    /// Number of ProveIR-available entries (both `ProveIr` and `Both`).
    pub fn prove_ir_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.availability.includes_prove_ir())
            .count()
    }

    /// Audit every entry against the invariants in the module docs.
    /// Additionally checks for duplicate names across the whole registry
    /// (should be impossible given [`BuiltinRegistry::push`]'s guard,
    /// but belt-and-suspenders).
    ///
    /// Returns the **first** violation. Callers that want the full list
    /// should iterate [`BuiltinRegistry::entries`] manually.
    pub fn audit(&self) -> Result<(), BuiltinAuditError> {
        // Per-entry audit.
        for entry in &self.entries {
            entry.audit()?;
        }

        // Registry-wide duplicate check.
        for (i, entry) in self.entries.iter().enumerate() {
            if self.entries[i + 1..].iter().any(|e| e.name == entry.name) {
                return Err(BuiltinAuditError::DuplicateName { name: entry.name });
            }
        }

        Ok(())
    }
}
