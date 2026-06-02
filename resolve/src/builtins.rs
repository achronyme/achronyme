//! The shared builtin registry.
//!
//! The single source of truth for all builtins. Both the VM compiler
//! and the ProveIR compiler dispatch through this registry — the VM
//! via `VmFnHandle` and ProveIR via `ProveIrLowerHandle`.
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
//! ## CRITICAL — Dependency direction
//!
//! The [`VmFnHandle`] and [`ProveIrLowerHandle`] types are **opaque
//! u32 indices**, not raw function pointers. This is deliberate and
//! must be preserved:
//!
//! - `compiler/` depends on `vm` AND `resolve` (natural).
//! - `ir/` depends on `resolve` but **must not** depend on `vm` —
//!   ProveIR is ZK-backend-agnostic and pulling in the VM runtime
//!   breaks that invariant.
//! - If [`VmFnHandle`] became `fn(&mut Vm, &[Value]) -> ...`, then
//!   `resolve` would gain a hard `vm` dep, `ir` would pull it
//!   transitively, and the architecture would silently collapse.
//!
//! **The invariant**: keep the handles as opaque indices. Each
//! backend owns its own `Vec<RealFn>` indexed by the handle. The
//! registry stores only metadata and indices. Dispatch is a two-hop:
//! name then handle then backend-owned fn. Zero dep cycle, zero trait
//! objects, zero allocation.
//!
//! The VM compiler owns a `vm_table: Vec<NativeFn>` and the ProveIR
//! compiler owns a `prove_ir_table: Vec<ProveIrLowerFn>`, both indexed
//! by the handles stored in [`BuiltinEntry`]. Do **not** refactor the
//! handles into concrete fn types — the dep-cycle risk is real and the
//! indirection is virtually free (one extra slice index per dispatch).

mod entry;
mod error;
mod handles;
mod registry;

pub use entry::BuiltinEntry;
pub use error::BuiltinAuditError;
pub use handles::{ProveIrLowerHandle, VmFnHandle};
pub use registry::BuiltinRegistry;

#[cfg(test)]
mod tests;
