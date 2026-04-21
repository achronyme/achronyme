//! `StubSink<F>` — the Phase 1 implementation of [`IrSink`].
//!
//! Stores every emitted `InstructionKind` in a plain `Vec` in the
//! order received. No hash-consing, no deduplication, no
//! side-effect separation — those land in Phase 2 (RFC §5.1-5.3).
//! The stub exists so the executor has something concrete to write
//! to today, and so the Phase 1 tests can assert exact emission
//! sequences.

use memory::field::{Bn254Fr, FieldBackend};

use crate::execute::IrSink;
use crate::intern::{InstructionKind, NodeId, NodeIdGen};

/// No-op sink backed by a growable vector.
#[derive(Debug)]
pub struct StubSink<F: FieldBackend = Bn254Fr> {
    instructions: Vec<InstructionKind<F>>,
    gen: NodeIdGen,
}

impl<F: FieldBackend> Default for StubSink<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> StubSink<F> {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            gen: NodeIdGen::default(),
        }
    }

    /// Full emission list in insertion order.
    pub fn instructions(&self) -> &[InstructionKind<F>] {
        &self.instructions
    }

    /// Consume the sink and return the emission vector.
    pub fn into_instructions(self) -> Vec<InstructionKind<F>> {
        self.instructions
    }
}

impl<F: FieldBackend> IrSink<F> for StubSink<F> {
    fn fresh_id(&mut self) -> NodeId {
        self.gen.fresh()
    }

    fn emit(&mut self, kind: InstructionKind<F>) {
        self.instructions.push(kind);
    }

    fn count(&self) -> usize {
        self.instructions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_is_order_preserving() {
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        sink.emit(InstructionKind::Input {
            result: a,
            name: "a".into(),
            visibility: crate::intern::Visibility::Witness,
        });
        let b = sink.fresh_id();
        sink.emit(InstructionKind::Input {
            result: b,
            name: "b".into(),
            visibility: crate::intern::Visibility::Witness,
        });
        let sum = sink.fresh_id();
        sink.emit(InstructionKind::Add {
            result: sum,
            lhs: a,
            rhs: b,
        });
        assert_eq!(sink.count(), 3);
        assert!(matches!(
            sink.instructions()[0],
            InstructionKind::Input { .. }
        ));
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::Add { .. }
        ));
    }

    #[test]
    fn no_deduplication_in_phase1() {
        // Two textually identical Add instructions must both land in
        // the sink — the interner in Phase 2 will dedup them; Phase 1
        // is deliberately naïve.
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        let b = sink.fresh_id();
        let r1 = sink.fresh_id();
        let r2 = sink.fresh_id();
        sink.emit(InstructionKind::Add {
            result: r1,
            lhs: a,
            rhs: b,
        });
        sink.emit(InstructionKind::Add {
            result: r2,
            lhs: a,
            rhs: b,
        });
        assert_eq!(sink.count(), 2);
    }

    #[test]
    fn ids_are_sequential_and_unique() {
        let mut sink = StubSink::<Bn254Fr>::new();
        let ids: Vec<NodeId> = (0..5).map(|_| sink.fresh_id()).collect();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.index(), i);
        }
    }
}
