//! Materialization: consume a [`NodeInterner<F>`] into a flat
//! `Vec<InstructionKind<F>>` (RFC §5.6 + §5.6.1).
//!
//! The walk is linear because `IndexMap` insertion order is already
//! topological — every pure node's operands were interned before it,
//! which means they appear earlier in the iteration and later
//! references are always to already-emitted ids.
//!
//! ## Ownership transfer (§5.6.1 route (c))
//!
//! [`NodeInterner::materialize`] takes `self` by value. As the
//! IndexMap is drained and the effects Vec consumed, their backing
//! allocations are freed before the function returns. The caller
//! sees only the newly-built `Vec<InstructionKind<F>>`, so peak
//! RSS during the handoff is `max(sizeof(interner), sizeof(Vec))`
//! rather than the sum — this is what Phase 4's `<2 GB peak` gate
//! depends on, since SHA-256(64) would otherwise transiently hold
//! both structures at ~5 GB.

use memory::field::FieldBackend;

use crate::intern::effect::SideEffect;
use crate::intern::interner::{Emission, NodeInterner};
use crate::intern::InstructionKind;

impl<F: FieldBackend> NodeInterner<F> {
    /// Consume the interner, producing a flat `Vec<InstructionKind<F>>`.
    ///
    /// Walks the `timeline` log so pure nodes and side-effects appear
    /// in their original emission order. This matters whenever a
    /// side-effect defines wires that later pure nodes consume —
    /// `Decompose`, `Input`, and `WitnessCall` all produce `NodeId`s
    /// that downstream `Add`/`Mul`/etc. reference. An earlier version
    /// split the stream into "pure prefix + effect suffix" and
    /// produced a forward-referencing Vec in exactly that case.
    pub fn materialize(self) -> Vec<InstructionKind<F>> {
        // De-structure so each field drops on its own schedule. Pulling
        // fields out by pattern avoids the partial-move pitfalls of
        // touching `self` through multiple accessors during the loop.
        let NodeInterner {
            nodes,
            effects,
            node_spans: _,
            effect_spans: _,
            timeline,
            next_node_id: _,
        } = self;

        let estimated = timeline.len();
        let mut out: Vec<InstructionKind<F>> = Vec::with_capacity(estimated);

        // Project into vectors we can index by insertion position.
        // `into_iter` drops each element as we consume it, so peak
        // overlap stays bounded.
        let pure_nodes: Vec<InstructionKind<F>> = nodes
            .into_iter()
            .map(|(key, meta)| key.into_instruction(meta.id))
            .collect();
        let mut effect_nodes: Vec<Option<SideEffect>> = effects.into_iter().map(Some).collect();

        for event in timeline {
            match event {
                Emission::Pure(idx) => {
                    let inst = pure_nodes
                        .get(idx)
                        .cloned()
                        .expect("timeline Pure index always in-bounds");
                    out.push(inst);
                }
                Emission::Effect(idx) => {
                    let eff = effect_nodes
                        .get_mut(idx)
                        .and_then(Option::take)
                        .expect("timeline Effect index visited exactly once");
                    out.push(SideEffect::into_instruction::<F>(eff));
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use memory::field::{Bn254Fr, FieldElement};

    use crate::intern::effect::SideEffect;
    use crate::intern::interner::NodeInterner;
    use crate::intern::key::NodeKey;
    use crate::intern::span::SpanRange;
    use crate::intern::{InstructionKind, Visibility};

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    #[test]
    fn empty_interner_materializes_to_empty_vec() {
        let ix = NodeInterner::<Bn254Fr>::new();
        let out = ix.materialize();
        assert!(out.is_empty());
    }

    #[test]
    fn const_add_const_materializes_in_topological_order() {
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
        let s = ix.intern_pure(NodeKey::Add(a, b), SpanRange::UNKNOWN);
        let out = ix.materialize();
        assert_eq!(out.len(), 3);
        match &out[0] {
            InstructionKind::Const { result, value } => {
                assert_eq!(*result, a);
                assert_eq!(*value, fe(1));
            }
            _ => panic!("pos 0 should be Const(1)"),
        }
        match &out[1] {
            InstructionKind::Const { result, value } => {
                assert_eq!(*result, b);
                assert_eq!(*value, fe(2));
            }
            _ => panic!("pos 1 should be Const(2)"),
        }
        match &out[2] {
            InstructionKind::Add { result, lhs, rhs } => {
                assert_eq!(*result, s);
                assert_eq!(*lhs, a);
                assert_eq!(*rhs, b);
            }
            _ => panic!("pos 2 should be Add"),
        }
    }

    #[test]
    fn dedup_is_preserved_through_materialize() {
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let a = ix.intern_pure(NodeKey::Const(fe(7)), SpanRange::UNKNOWN);
        let _ = ix.intern_pure(NodeKey::Add(a, a), SpanRange::UNKNOWN);
        let _ = ix.intern_pure(NodeKey::Add(a, a), SpanRange::UNKNOWN);
        let _ = ix.intern_pure(NodeKey::Add(a, a), SpanRange::UNKNOWN);
        let out = ix.materialize();
        // 1 Const + 1 Add (3 duplicate intern calls collapsed to one).
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn effects_appended_after_pure_prefix() {
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        let out_id = ix.reserve_opaque_id();
        ix.emit_effect(
            SideEffect::RangeCheck {
                result: out_id,
                operand: a,
                bits: 8,
            },
            SpanRange::UNKNOWN,
        );
        let out = ix.materialize();
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], InstructionKind::Const { .. }));
        assert!(matches!(out[1], InstructionKind::RangeCheck { .. }));
    }

    #[test]
    fn duplicate_effects_both_appear() {
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
        let r1 = ix.reserve_opaque_id();
        let r2 = ix.reserve_opaque_id();
        ix.emit_effect(
            SideEffect::AssertEq {
                result: r1,
                lhs: a,
                rhs: b,
                message: None,
            },
            SpanRange::UNKNOWN,
        );
        ix.emit_effect(
            SideEffect::AssertEq {
                result: r2,
                lhs: a,
                rhs: b,
                message: None,
            },
            SpanRange::UNKNOWN,
        );
        let out = ix.materialize();
        let assert_count = out
            .iter()
            .filter(|i| matches!(i, InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(assert_count, 2, "side-effects must never dedup");
    }

    #[test]
    fn round_trip_preserves_operand_ids() {
        // After materialize, every operand id referenced by a later
        // instruction must have appeared as a prior `result` — this
        // is the "topological order" contract.
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
        let c = ix.intern_pure(NodeKey::Mul(a, b), SpanRange::UNKNOWN);
        let _ = ix.intern_pure(NodeKey::Add(c, a), SpanRange::UNKNOWN);

        let out = ix.materialize();

        let mut seen_ids: std::collections::HashSet<_> = std::collections::HashSet::new();
        for instr in &out {
            let result = instr.result();
            for operand in [
                operand_of(instr, 0),
                operand_of(instr, 1),
                operand_of(instr, 2),
            ]
            .into_iter()
            .flatten()
            {
                assert!(
                    seen_ids.contains(&operand),
                    "operand {operand:?} referenced before definition"
                );
            }
            seen_ids.insert(result);
        }
    }

    #[test]
    fn side_effect_output_binds_through_materialize() {
        let mut ix = NodeInterner::<Bn254Fr>::new();
        let wire = ix.reserve_opaque_id();
        ix.emit_effect(
            SideEffect::Input {
                output: wire,
                name: "x".into(),
                visibility: Visibility::Public,
            },
            SpanRange::UNKNOWN,
        );
        let out = ix.materialize();
        match &out[0] {
            InstructionKind::Input {
                result,
                name,
                visibility,
            } => {
                assert_eq!(*result, wire);
                assert_eq!(name, "x");
                assert_eq!(*visibility, Visibility::Public);
            }
            _ => panic!("expected Input"),
        }
    }

    /// Tiny helper that pulls out the `n`-th operand of an instruction
    /// for the topological-order check above. Covers the variants used
    /// in the test only.
    fn operand_of(instr: &InstructionKind<Bn254Fr>, n: usize) -> Option<crate::intern::NodeId> {
        use InstructionKind as K;
        match (instr, n) {
            (K::Add { lhs, .. } | K::Mul { lhs, .. }, 0) => Some(*lhs),
            (K::Add { rhs, .. } | K::Mul { rhs, .. }, 1) => Some(*rhs),
            _ => None,
        }
    }
}
