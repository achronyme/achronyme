//! The shared builtin registry.
//!
//! Replaces the divergent pair of dispatch tables:
//! - `vm/src/specs.rs:NATIVE_TABLE` (14 VM natives)
//! - `ir/src/prove_ir/compiler.rs:lower_builtin` (9 ProveIR builtins)
//!
//! ## Audit invariants
//!
//! The [`BuiltinRegistry::audit`] method is the heart of this crate's
//! value proposition. It runs once at registry construction time and
//! enforces four rules that catch an entire class of bugs at build time:
//!
//! 1. **Both implies both**: every [`Availability::Both`] entry must
//!    declare both `vm_fn` AND `prove_ir_lower`. Missing one is a logic
//!    bug — catches the `mux` ProveIR-only gap (1.1 in the gaps doc)
//!    before any user code can trip it.
//! 2. **Vm rejects prove impl**: an [`Availability::Vm`] entry that also
//!    declares `prove_ir_lower` is self-contradictory. The author either
//!    meant [`Availability::Both`] or shouldn't have declared the
//!    lowering.
//! 3. **ProveIr rejects vm impl**: symmetric to rule 2.
//! 4. **Required impls present**: [`Availability::Vm`] needs `vm_fn`
//!    (can't be callable from VM without an implementation); same for
//!    ProveIR.
//!
//! These rules are structural — no test data, no user code, just the
//! registry shape. If the registry passes audit, every [`Availability`]
//! is honored correctly.
//!
//! ## ⚠ CRITICAL FOR PHASE 2 — Dependency direction
//!
//! The [`VmFnHandle`] and [`ProveIrLowerHandle`] types are **opaque
//! u32 indices**, not raw function pointers. This is deliberate and
//! must be preserved when Phase 2 wires the real implementations:
//!
//! - `compiler/` depends on `vm` AND `resolve` (natural).
//! - `ir/` depends on `resolve` but **must not** depend on `vm` —
//!   ProveIR is ZK-backend-agnostic and pulling in the VM runtime
//!   breaks that invariant.
//! - If [`VmFnHandle`] became `fn(&mut Vm, &[Value]) -> ...`, then
//!   `resolve` would gain a hard `vm` dep, `ir` would pull it
//!   transitively, and the architecture would silently collapse.
//!
//! **The fix, forever**: keep the handles as opaque indices. Each
//! backend owns its own `Vec<RealFn>` indexed by the handle. The
//! registry stores only metadata + indices. Dispatch is a two-hop:
//! name → handle → backend-owned fn. Zero dep cycle, zero trait
//! objects, zero allocation.
//!
//! Phase 2 will extend this module with a `vm_table: Vec<NativeFn>`
//! inside the VM compiler and a `prove_ir_table: Vec<ProveIrLowerFn>`
//! inside the ProveIR compiler, both indexed by the handles stored
//! in [`BuiltinEntry`]. Do **not** refactor the handles into concrete
//! fn types — the dep-cycle risk is real and the indirection is
//! virtually free (one extra slice index per dispatch).

use crate::symbol::{Arity, Availability};
use std::fmt;

/// Opaque handle to a VM native function implementation.
///
/// The handle is a u32 index into a backend-owned `Vec<NativeFn>`. See
/// the module docs above for why this crate holds an index and not a
/// raw function pointer — the TL;DR is "dep cycle with `vm`". Phase 1
/// uses placeholder handle values (typically 0) because no real
/// dispatch is wired yet; Phase 2 will populate real indices as it
/// registers natives with the VM side.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct VmFnHandle(pub u32);

impl VmFnHandle {
    /// Sentinel used by tests and placeholder entries before Phase 2
    /// wires real impls. Production code should never observe this
    /// after Phase 2.
    pub const PLACEHOLDER: Self = VmFnHandle(0);

    /// Raw index view.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Opaque handle to a ProveIR lowering callback.
///
/// Symmetric to [`VmFnHandle`]: a u32 index into a backend-owned
/// `Vec<ProveIrLowerFn>` that lives inside the `ir` crate. This
/// crate carries only the handle so `ir` never pulls in VM types
/// via `resolve`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProveIrLowerHandle(pub u32);

impl ProveIrLowerHandle {
    /// Sentinel used by tests and placeholder entries before Phase 2
    /// wires real impls.
    pub const PLACEHOLDER: Self = ProveIrLowerHandle(0);

    /// Raw index view.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// One entry in the [`BuiltinRegistry`].
///
/// Declares everything the compilers need to know about a builtin: its
/// name (for diagnostics and for the resolver pass's name lookup), its
/// arity (for early validation), its availability (for audit), and the
/// pointers to its implementation(s).
#[derive(Debug, Clone)]
pub struct BuiltinEntry {
    /// The canonical name users write in source code. `poseidon`,
    /// `assert_eq`, `mux`, etc. Unique within the registry.
    pub name: &'static str,
    /// Expected argument count. Checked by the resolver pass before
    /// dispatch; individual impls may validate further.
    pub arity: Arity,
    /// Which contexts can call this builtin. Enforced structurally by
    /// [`BuiltinRegistry::audit`].
    pub availability: Availability,
    /// VM runtime implementation handle. Required for
    /// [`Availability::Vm`] and [`Availability::Both`]; must be `None`
    /// for [`Availability::ProveIr`].
    pub vm_fn: Option<VmFnHandle>,
    /// ProveIR lowering callback handle. Required for
    /// [`Availability::ProveIr`] and [`Availability::Both`]; must be
    /// `None` for [`Availability::Vm`].
    pub prove_ir_lower: Option<ProveIrLowerHandle>,
}

impl BuiltinEntry {
    /// Audit just this entry against the four invariants documented at
    /// the module level. Returns a specific error describing the
    /// violation, or `Ok(())`.
    pub fn audit(&self) -> Result<(), BuiltinAuditError> {
        match self.availability {
            Availability::Both => {
                if self.vm_fn.is_none() {
                    return Err(BuiltinAuditError::BothMissingVm { name: self.name });
                }
                if self.prove_ir_lower.is_none() {
                    return Err(BuiltinAuditError::BothMissingProveIr { name: self.name });
                }
            }
            Availability::Vm => {
                if self.vm_fn.is_none() {
                    return Err(BuiltinAuditError::VmMissingImpl { name: self.name });
                }
                if self.prove_ir_lower.is_some() {
                    return Err(BuiltinAuditError::VmDeclaresProveIr { name: self.name });
                }
            }
            Availability::ProveIr => {
                if self.prove_ir_lower.is_none() {
                    return Err(BuiltinAuditError::ProveIrMissingImpl { name: self.name });
                }
                if self.vm_fn.is_some() {
                    return Err(BuiltinAuditError::ProveIrDeclaresVm { name: self.name });
                }
            }
        }
        Ok(())
    }
}

/// The set of all registered builtins in a compilation session.
///
/// Phase 1 ships with an empty [`BuiltinRegistry::default()`]. Phase 2
/// populates it with the ~23 existing builtins (14 VM + 9 ProveIR,
/// deduplicated), wires both compilers to read from it, and removes the
/// parallel `NATIVE_TABLE` / ProveIR match.
///
/// Fields are **private** to protect the uniqueness invariant maintained
/// by [`BuiltinRegistry::push`]. Use [`BuiltinRegistry::entries`],
/// [`BuiltinRegistry::len`], [`BuiltinRegistry::lookup`], etc. for read
/// access.
#[derive(Debug, Clone, Default)]
pub struct BuiltinRegistry {
    /// The entries in declaration order. The order is NOT significant
    /// to dispatch (we use `name` as the key) but is preserved for
    /// stable diagnostic output.
    entries: Vec<BuiltinEntry>,
}

impl BuiltinRegistry {
    /// Create an empty registry. Useful for tests; production code should
    /// use [`BuiltinRegistry::default()`] which (starting in Phase 2)
    /// returns the populated production registry.
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
    /// Phase 2's resolver pass will call this to construct
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

/// Errors produced by [`BuiltinRegistry::audit`] and [`BuiltinEntry::audit`].
///
/// Every variant names the offending builtin and explains the violation.
/// The compiler crate in Phase 2 will wrap these into full diagnostics
/// with suggestions; Phase 1 keeps them as plain enum variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinAuditError {
    /// [`Availability::Both`] entry missing its VM implementation.
    BothMissingVm {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Both`] entry missing its ProveIR lowering.
    BothMissingProveIr {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Vm`] entry missing its VM implementation.
    VmMissingImpl {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Vm`] entry also declares a ProveIR lowering —
    /// probably meant to be [`Availability::Both`].
    VmDeclaresProveIr {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::ProveIr`] entry missing its lowering.
    ProveIrMissingImpl {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::ProveIr`] entry also declares a VM implementation.
    ProveIrDeclaresVm {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// Two different entries share the same `name`.
    DuplicateName {
        /// The colliding name.
        name: &'static str,
    },
}

impl fmt::Display for BuiltinAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothMissingVm { name } => write!(
                f,
                "builtin `{name}` declared as `Both` but missing VM implementation \
                 (`vm_fn: None`). Either provide a VM impl or change availability \
                 to `ProveIr`."
            ),
            Self::BothMissingProveIr { name } => write!(
                f,
                "builtin `{name}` declared as `Both` but missing ProveIR lowering \
                 (`prove_ir_lower: None`). Either provide a ProveIR lowering or \
                 change availability to `Vm`."
            ),
            Self::VmMissingImpl { name } => write!(
                f,
                "builtin `{name}` declared as `Vm` but has no `vm_fn` — Vm \
                 availability requires a VM implementation."
            ),
            Self::VmDeclaresProveIr { name } => write!(
                f,
                "builtin `{name}` declared as `Vm` but also declares \
                 `prove_ir_lower`. Did you mean `Availability::Both`?"
            ),
            Self::ProveIrMissingImpl { name } => write!(
                f,
                "builtin `{name}` declared as `ProveIr` but has no \
                 `prove_ir_lower` — ProveIr availability requires a lowering."
            ),
            Self::ProveIrDeclaresVm { name } => write!(
                f,
                "builtin `{name}` declared as `ProveIr` but also declares \
                 `vm_fn`. Did you mean `Availability::Both`?"
            ),
            Self::DuplicateName { name } => write!(
                f,
                "builtin `{name}` is registered more than once — every registry \
                 entry must have a unique name."
            ),
        }
    }
}

impl std::error::Error for BuiltinAuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        name: &'static str,
        availability: Availability,
        vm: bool,
        prove: bool,
    ) -> BuiltinEntry {
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
}
