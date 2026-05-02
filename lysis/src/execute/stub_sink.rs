//! `StubSink<F>` — the no-op implementation of [`IrSink`].
//!
//! Stores every emitted `InstructionKind` in a plain `Vec` in the
//! order received. No hash-consing, no deduplication, no
//! side-effect separation — those features live in [`InterningSink`]
//! (RFC §5.1-5.3). The stub exists so the executor has something
//! concrete to write to and so tests can assert exact emission
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
    fn no_deduplication_in_stub_sink() {
        // Two textually identical Add instructions must both land in
        // the sink — the interning sink dedups them; the stub is
        // deliberately naïve.
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

    #[test]
    fn intern_pure_default_path_does_not_dedup() {
        // StubSink uses the default `intern_pure` impl: fresh_id +
        // emit. No hash-consing, so two identical Adds produce two
        // distinct ids and two distinct entries.
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        let b = sink.fresh_id();
        let id1 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
        let id2 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
        assert_ne!(id1, id2);
        assert_eq!(sink.count(), 2);
    }

    #[test]
    fn emit_effect_default_path_retains_duplicates() {
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        let b = sink.fresh_id();
        let r1 = sink.fresh_id();
        let r2 = sink.fresh_id();
        sink.emit_effect(InstructionKind::AssertEq {
            result: r1,
            lhs: a,
            rhs: b,
            message: None,
        });
        sink.emit_effect(InstructionKind::AssertEq {
            result: r2,
            lhs: a,
            rhs: b,
            message: None,
        });
        assert_eq!(sink.count(), 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "intern_pure called on side-effect variant")]
    fn intern_pure_rejects_side_effect_in_debug() {
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        // Debug-assert — in release this falls through to `emit` and
        // silently produces non-sensical output. Test only runs in debug.
        let _ = sink.intern_pure(InstructionKind::AssertEq {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: a,
            message: None,
        });
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "emit_effect called on pure variant")]
    fn emit_effect_rejects_pure_in_debug() {
        let mut sink = StubSink::<Bn254Fr>::new();
        let a = sink.fresh_id();
        let b = sink.fresh_id();
        sink.emit_effect(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
    }
}
