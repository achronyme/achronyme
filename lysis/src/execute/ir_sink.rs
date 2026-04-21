//! `IrSink<F>` — the trait over anything that can receive IR emissions
//! from the Lysis executor.
//!
//! Phase 1 ships a single implementation: [`crate::execute::StubSink`],
//! which stores emissions in a `Vec<InstructionKind<F>>` in the order
//! they arrive, without hash-consing or deduplication. Phase 2 adds a
//! second implementation backed by the real `NodeInterner`, which
//! intern-dedups pure nodes while keeping side-effecting ones in
//! their original order via a separate `EffectId` channel.
//!
//! The trait is deliberately minimal so both implementations have
//! the same public surface from the executor's point of view.

use memory::field::FieldBackend;

use crate::intern::{InstructionKind, NodeId};

/// Destination for executor emissions. Every node-producing opcode
/// flows through here.
///
/// # Identity allocation
///
/// The executor allocates a fresh `NodeId` via [`Self::fresh_id`]
/// *before* constructing the `InstructionKind` that will carry it.
/// This matches how `ir::IrProgram` allocates `SsaVar`s via
/// `fresh_var()`: the writer knows its result up front, so that
/// dependent instructions can reference the id even while the
/// producing instruction is still being assembled.
pub trait IrSink<F: FieldBackend> {
    /// Produce a fresh node id. The executor builds an
    /// `InstructionKind` around this id and then passes it to
    /// [`Self::emit`].
    fn fresh_id(&mut self) -> NodeId;

    /// Record an emitted instruction. Implementations may intern
    /// pure values (Phase 2) but must *never* dedup the variants
    /// classified as side-effects by
    /// [`InstructionKind::is_side_effect`].
    fn emit(&mut self, kind: InstructionKind<F>);

    /// Count of instructions recorded so far. Mainly for tests and
    /// diagnostics.
    fn count(&self) -> usize;
}
