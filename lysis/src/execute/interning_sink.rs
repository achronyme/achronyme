//! `InterningSink<F>` — the Phase 2 [`IrSink`] backed by a real
//! [`NodeInterner<F>`].
//!
//! Pure instructions flow through the interner's hash-consing table:
//! two textually-identical calls of `intern_pure(Add(a, b))` return
//! the same `NodeId`. Side-effects flow through the separate ordered
//! channel and never dedup.
//!
//! `fresh_id` is a pass-through to
//! [`NodeInterner::reserve_opaque_id`]; the executor calls it to
//! reserve ids for `Input` wires, `Decompose` bit results, and
//! `WitnessCall` outputs before constructing the side-effect
//! `InstructionKind`.
//!
//! When the executor finishes, call [`InterningSink::materialize`]
//! (or [`InterningSink::into_interner`] then
//! [`NodeInterner::materialize`]) to produce the flat
//! `Vec<InstructionKind<F>>` that the R1CS backend consumes. The
//! interner drops before the Vec returns (RFC §5.6.1 route (c)).

use memory::field::{Bn254Fr, FieldBackend};

use crate::execute::IrSink;
use crate::intern::{
    InstructionKind, NodeId, NodeInterner, NodeKey, SideEffect, SpanRange,
};

/// `IrSink` that performs real per-instruction hash-consing.
#[derive(Debug, Clone)]
pub struct InterningSink<F: FieldBackend = Bn254Fr> {
    interner: NodeInterner<F>,
}

impl<F: FieldBackend> Default for InterningSink<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> InterningSink<F> {
    pub fn new() -> Self {
        Self {
            interner: NodeInterner::new(),
        }
    }

    /// Borrow the underlying interner — mainly for tests and the
    /// determinism harness.
    pub fn interner(&self) -> &NodeInterner<F> {
        &self.interner
    }

    /// Consume and hand back the interner. Callers chain
    /// `.into_interner().materialize()` when they want both the raw
    /// interner data (for diagnostics) and the flat IR.
    pub fn into_interner(self) -> NodeInterner<F> {
        self.interner
    }

    /// Convenience shortcut for `into_interner().materialize()`.
    pub fn materialize(self) -> Vec<InstructionKind<F>> {
        self.interner.materialize()
    }

    /// Number of unique pure nodes the interner has accumulated.
    pub fn pure_len(&self) -> usize {
        self.interner.pure_len()
    }

    /// Number of side-effects recorded.
    pub fn effect_len(&self) -> usize {
        self.interner.effect_len()
    }
}

impl<F: FieldBackend> IrSink<F> for InterningSink<F> {
    fn fresh_id(&mut self) -> NodeId {
        self.interner.reserve_opaque_id()
    }

    fn emit(&mut self, kind: InstructionKind<F>) {
        // Compatibility path for callers that still go through the
        // old `emit`: dispatch by variant to the correct channel.
        if kind.is_side_effect() {
            let eff = SideEffect::from_instruction(kind)
                .expect("is_side_effect classified it as side-effect");
            self.interner.emit_effect(eff, SpanRange::UNKNOWN);
        } else {
            // `emit` arrives with a fresh id already embedded — we
            // throw that away and let the interner assign a canonical
            // one (which may dedup to an earlier id).
            let key = NodeKey::from_instruction(&kind)
                .expect("is_side_effect classified it as pure");
            self.interner.intern_pure(key, SpanRange::UNKNOWN);
        }
    }

    fn intern_pure(&mut self, kind: InstructionKind<F>) -> NodeId {
        debug_assert!(
            !kind.is_side_effect(),
            "intern_pure called on side-effect variant"
        );
        let key = NodeKey::from_instruction(&kind)
            .expect("checked pure via is_side_effect");
        self.interner.intern_pure(key, SpanRange::UNKNOWN)
    }

    fn emit_effect(&mut self, kind: InstructionKind<F>) {
        debug_assert!(
            kind.is_side_effect(),
            "emit_effect called on pure variant"
        );
        let eff = SideEffect::from_instruction(kind)
            .expect("checked side-effect via is_side_effect");
        self.interner.emit_effect(eff, SpanRange::UNKNOWN);
    }

    fn count(&self) -> usize {
        self.pure_len() + self.effect_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::field::FieldElement;

    use crate::intern::Visibility;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    // ------------------------------------------------------------------
    // Pure dedup.
    // ------------------------------------------------------------------

    #[test]
    fn identical_adds_collapse_to_single_node() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let b = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(2),
        });
        let s1 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
        let s2 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
        assert_eq!(s1, s2);
        assert_eq!(sink.pure_len(), 3); // 2 Consts + 1 Add (deduped)
        assert_eq!(sink.count(), 3);
    }

    #[test]
    fn distinct_operands_produce_distinct_ids() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let b = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(2),
        });
        let s1 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: a,
            rhs: b,
        });
        let s2 = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: b,
            rhs: a,
        });
        assert_ne!(s1, s2);
        assert_eq!(sink.pure_len(), 4);
    }

    // ------------------------------------------------------------------
    // Side-effects never dedup.
    // ------------------------------------------------------------------

    #[test]
    fn identical_asserts_both_kept() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let b = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(2),
        });
        let r1 = sink.fresh_id();
        sink.emit_effect(InstructionKind::AssertEq {
            result: r1,
            lhs: a,
            rhs: b,
            message: None,
        });
        let r2 = sink.fresh_id();
        sink.emit_effect(InstructionKind::AssertEq {
            result: r2,
            lhs: a,
            rhs: b,
            message: None,
        });
        assert_ne!(r1, r2);
        assert_eq!(sink.effect_len(), 2);
        assert_eq!(sink.count(), 4); // 2 Consts + 2 AssertEq
    }

    #[test]
    fn inputs_get_fresh_ids() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let i1 = sink.fresh_id();
        sink.emit_effect(InstructionKind::Input {
            result: i1,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let i2 = sink.fresh_id();
        sink.emit_effect(InstructionKind::Input {
            result: i2,
            name: "x".into(), // identical name
            visibility: Visibility::Public,
        });
        assert_ne!(i1, i2);
        assert_eq!(sink.effect_len(), 2);
    }

    // ------------------------------------------------------------------
    // Materialize.
    // ------------------------------------------------------------------

    #[test]
    fn materialize_produces_deduped_flat_vec() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(7),
        });
        // Six identical Adds — all collapse to one.
        for _ in 0..6 {
            sink.intern_pure(InstructionKind::Add {
                result: NodeId::from_zero_based(0),
                lhs: a,
                rhs: a,
            });
        }
        let flat = sink.materialize();
        assert_eq!(flat.len(), 2); // 1 Const + 1 Add
    }

    #[test]
    fn materialize_keeps_side_effects_in_order() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let r1 = sink.fresh_id();
        sink.emit_effect(InstructionKind::RangeCheck {
            result: r1,
            operand: a,
            bits: 8,
        });
        let r2 = sink.fresh_id();
        sink.emit_effect(InstructionKind::RangeCheck {
            result: r2,
            operand: a,
            bits: 16,
        });
        let flat = sink.materialize();
        let ranges: Vec<_> = flat
            .iter()
            .filter_map(|i| match i {
                InstructionKind::RangeCheck { bits, .. } => Some(*bits),
                _ => None,
            })
            .collect();
        assert_eq!(ranges, vec![8, 16]);
    }

    // ------------------------------------------------------------------
    // emit() compatibility path.
    // ------------------------------------------------------------------

    #[test]
    fn legacy_emit_routes_pure_through_intern() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let b = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(2),
        });
        // Emit two identical Adds through the legacy path.
        sink.emit(InstructionKind::Add {
            result: NodeId::from_zero_based(99), // ignored
            lhs: a,
            rhs: b,
        });
        sink.emit(InstructionKind::Add {
            result: NodeId::from_zero_based(100),
            lhs: a,
            rhs: b,
        });
        // Deduped despite going through the old `emit` entry point.
        assert_eq!(sink.pure_len(), 3);
    }

    #[test]
    fn legacy_emit_routes_effects_through_channel() {
        let mut sink = InterningSink::<Bn254Fr>::new();
        let a = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let r1 = sink.fresh_id();
        sink.emit(InstructionKind::RangeCheck {
            result: r1,
            operand: a,
            bits: 8,
        });
        let r2 = sink.fresh_id();
        sink.emit(InstructionKind::RangeCheck {
            result: r2,
            operand: a,
            bits: 8,
        });
        assert_eq!(sink.effect_len(), 2);
    }
}
