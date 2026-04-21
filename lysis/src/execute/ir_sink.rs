//! `IrSink<F>` — the trait over anything that can receive IR emissions
//! from the Lysis executor.
//!
//! Two implementations:
//!
//! - [`crate::execute::StubSink`] (Phase 1) keeps every emission in a
//!   plain `Vec<InstructionKind<F>>`, no dedup. Still used by tests
//!   and benchmarks to measure the "no hash-consing" baseline.
//! - [`crate::execute::InterningSink`] (Phase 2) is backed by a real
//!   [`NodeInterner<F>`]. Pure ops that intern to the same
//!   [`NodeKey<F>`] collapse to a single entry; side-effects flow
//!   through a separate ordered channel that never dedups.
//!
//! The executor works at the `InstructionKind<F>` level regardless of
//! the sink behind it. The trait methods translate that shape into
//! the sink's native representation:
//!
//! - [`Self::intern_pure`] accepts a pure `InstructionKind`. The
//!   `result` field is a placeholder — the sink chooses the canonical
//!   id (`StubSink` assigns a fresh one; `InterningSink` may return an
//!   earlier id if the structural key already exists) and returns it.
//! - [`Self::emit_effect`] accepts a side-effect `InstructionKind`.
//!   All output `NodeId`s must already be filled in (reserved via
//!   [`Self::fresh_id`]); effects never dedup, so the id allocation
//!   is purely the caller's responsibility.
//!
//! [`NodeInterner<F>`]: crate::intern::NodeInterner
//! [`NodeKey<F>`]: crate::intern::NodeKey

use memory::field::FieldBackend;

use crate::intern::{InstructionKind, NodeId};

/// Destination for executor emissions. Every node-producing opcode
/// flows through here.
pub trait IrSink<F: FieldBackend> {
    /// Reserve a fresh, opaque [`NodeId`]. The caller binds it into a
    /// register and then uses it inside a side-effect `InstructionKind`
    /// (as an `Input` wire, a `Decompose` bit result, a `WitnessCall`
    /// output, etc.) before passing the kind to [`Self::emit_effect`].
    fn fresh_id(&mut self) -> NodeId;

    /// Record an emitted instruction without interning. Kept so the
    /// Phase 1 executor path (which mints a fresh id via `fresh_id`
    /// and then calls `emit` with the id embedded in `kind`) continues
    /// to compile while the dispatch loop is migrated to
    /// [`Self::intern_pure`] / [`Self::emit_effect`] in a follow-up
    /// commit. Scheduled for removal once the migration lands.
    fn emit(&mut self, kind: InstructionKind<F>);

    /// Intern a pure instruction.
    ///
    /// The sink examines the structural key encoded by `kind`; if an
    /// equivalent one is already in the intern table, the previously
    /// assigned id is returned and no additional state is recorded
    /// beyond appending to the span list. Otherwise a fresh id is
    /// assigned and the kind is recorded.
    ///
    /// The `result` field of `kind` is ignored — the sink chooses the
    /// id. Implementors may `debug_assert!(!kind.is_side_effect())`.
    ///
    /// Default implementation routes through `fresh_id` + `emit` with
    /// the new id stamped in — that's Phase 1 semantics (no dedup).
    /// `InterningSink` overrides this to do real hash-consing.
    fn intern_pure(&mut self, kind: InstructionKind<F>) -> NodeId {
        debug_assert!(
            !kind.is_side_effect(),
            "intern_pure called on side-effect variant"
        );
        let id = self.fresh_id();
        let kind = kind.with_result(id);
        self.emit(kind);
        id
    }

    /// Record a side-effect instruction. The sink appends it to the
    /// effect channel in emission order; no deduplication happens.
    /// `kind` must be a side-effect variant and must already carry the
    /// `NodeId`s the caller reserved via [`Self::fresh_id`].
    ///
    /// Default implementation delegates to [`Self::emit`] — correct
    /// semantically because `emit` already never deduplicates. The
    /// separate method exists so hash-consing sinks can tell the two
    /// apart statically.
    fn emit_effect(&mut self, kind: InstructionKind<F>) {
        debug_assert!(kind.is_side_effect(), "emit_effect called on pure variant");
        self.emit(kind);
    }

    /// Count of items recorded — pure emissions (unique), plus
    /// side-effects. Mainly for tests and diagnostics.
    fn count(&self) -> usize;
}
