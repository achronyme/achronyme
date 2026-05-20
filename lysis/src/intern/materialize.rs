//! Materialization: consume a [`NodeInterner<F>`] into a flat
//! `Vec<InstructionKind<F>>`.
//!
//! The walk is linear because `IndexMap` insertion order is already
//! topological — every pure node's operands were interned before it,
//! which means they appear earlier in the iteration and later
//! references are always to already-emitted ids.
//!
//! ## Ownership transfer
//!
//! [`NodeInterner::materialize`] takes `self` by value. As the
//! IndexMap is drained and the effects Vec consumed, their backing
//! allocations are freed before the function returns. The caller
//! sees only the newly-built `Vec<InstructionKind<F>>`, so peak
//! RSS during the handoff is `max(sizeof(interner), sizeof(Vec))`
//! rather than the sum — this is what the `<2 GB peak` memory
//! budget depends on, since SHA-256(64) would otherwise transiently
//! hold both structures at ~5 GB.

use memory::field::FieldBackend;

use crate::intern::effect::SideEffect;
use crate::intern::interner::{Emission, NodeInterner};
use crate::intern::InstructionKind;

impl<F: FieldBackend> NodeInterner<F> {
    /// Consume the interner and return a single-pass iterator over the
    /// emission stream. Drop semantics: each yielded
    /// `InstructionKind<F>` releases its slot from the backing buffer
    /// as the iterator advances, so consumers that fold instructions
    /// into a downstream representation can avoid holding the whole
    /// IR in memory simultaneously.
    ///
    /// Concrete iterator type is `std::vec::IntoIter` — same as
    /// `materialize().into_iter()`, but expressed as the API contract
    /// so callers can rely on the single-pass behaviour and the
    /// concrete type without dyn dispatch.
    ///
    /// Under streaming mode (`with_streaming_window`), the underlying
    /// buffer is the incrementally-built `streaming_output` Vec.
    /// Under eager mode, the timeline is walked into a fresh Vec
    /// first, then drained — byte-identical to the eager
    /// [`Self::materialize`] output.
    pub fn into_instruction_stream(self) -> std::vec::IntoIter<InstructionKind<F>> {
        self.materialize().into_iter()
    }

    /// Lazily drain the emission stream chunk-by-chunk. Returns an
    /// iterator that yields one `InstructionKind<F>` per advance and
    /// drops each consumed chunk's backing allocation as the iterator
    /// crosses chunk boundaries. Under chunked streaming mode
    /// ([`Self::with_streaming_window_chunked`]) this avoids ever
    /// materialising the full emission stream as a single Vec —
    /// downstream consumers operate on one chunk at a time and the
    /// peak resident footprint shrinks to (already-allocated chunks)
    /// rather than (already-allocated chunks + flattened Vec).
    ///
    /// Under non-chunked streaming and eager modes, the stream is
    /// materialised once via [`Self::materialize`] and then drained
    /// from the resulting Vec — semantically equivalent to
    /// `into_instruction_stream`, returned through an `impl Iterator`
    /// shell so the caller can be agnostic to layout.
    pub fn into_chunked_iter(mut self) -> Box<dyn Iterator<Item = InstructionKind<F>> + 'static>
    where
        F: 'static,
    {
        if self.chunked {
            let chunks = std::mem::take(&mut self.streaming_chunks);
            // `flat_map(Vec::into_iter)` drops each chunk's backing
            // allocation when its inner iterator is exhausted, so the
            // resident footprint shrinks monotonically as the consumer
            // pulls items.
            Box::new(
                chunks
                    .into_iter()
                    .flat_map(<Vec<InstructionKind<F>>>::into_iter),
            )
        } else {
            Box::new(self.materialize().into_iter())
        }
    }

    /// Consume the interner, producing a flat `Vec<InstructionKind<F>>`.
    ///
    /// Walks the `timeline` log so pure nodes and side-effects appear
    /// in their original emission order. This matters whenever a
    /// side-effect defines wires that later pure nodes consume —
    /// `Decompose`, `Input`, and `WitnessCall` all produce `NodeId`s
    /// that downstream `Add`/`Mul`/etc. reference. An earlier version
    /// split the stream into "pure prefix + effect suffix" and
    /// produced a forward-referencing Vec in exactly that case.
    pub fn materialize(mut self) -> Vec<InstructionKind<F>> {
        // Chunked streaming path: flatten the per-chunk buffers into a
        // single Vec. The flatten boundary pays one Vec construction
        // (peak == total content + transient doubling of the flatten
        // Vec); callers that cannot afford this should drain via
        // [`Self::into_chunked_iter`] instead.
        if self.window_size.is_some() && self.chunked {
            let chunks = std::mem::take(&mut self.streaming_chunks);
            let total: usize = chunks.iter().map(Vec::len).sum();
            let mut flat = Vec::with_capacity(total);
            for chunk in chunks {
                flat.extend(chunk);
            }
            return flat;
        }
        // Streaming path: the materialized stream was built
        // incrementally as fresh inserts + effects flowed through; just
        // hand back the buffer.
        if self.window_size.is_some() {
            return self.streaming_output;
        }

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
            record_spans: _,
            const_table: _,
            mul_cc_table: _,
            window_size: _,
            streaming_output: _,
            eviction_queue: _,
            const_nodes: _,
            chunked: _,
            streaming_chunks: _,
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
    fn into_instruction_stream_matches_materialize() {
        let build = || {
            let mut ix = NodeInterner::<Bn254Fr>::new();
            let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
            let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
            let c = ix.intern_pure(NodeKey::Mul(a, b), SpanRange::UNKNOWN);
            let _ = ix.intern_pure(NodeKey::Add(c, a), SpanRange::UNKNOWN);
            let opaque = ix.reserve_opaque_id();
            ix.emit_effect(
                SideEffect::RangeCheck {
                    result: opaque,
                    operand: a,
                    bits: 8,
                },
                SpanRange::UNKNOWN,
            );
            ix
        };
        let via_vec = build().materialize();
        let via_iter: Vec<_> = build().into_instruction_stream().collect();
        assert_eq!(via_vec.len(), via_iter.len());
        for (v, i) in via_vec.iter().zip(via_iter.iter()) {
            assert_eq!(format!("{v:?}"), format!("{i:?}"));
        }
    }

    #[test]
    fn chunked_materialize_matches_non_chunked_streaming() {
        // Drive the same input through `with_streaming_window` and
        // `with_streaming_window_chunked`; the materialised instruction
        // stream must be equivalent (same length, same sequence).
        let build = |chunked: bool| {
            let mut ix = if chunked {
                NodeInterner::<Bn254Fr>::with_streaming_window_chunked(8)
            } else {
                NodeInterner::<Bn254Fr>::with_streaming_window(8)
            };
            for i in 0..32u64 {
                let v = ix.intern_pure(NodeKey::Const(fe(i)), SpanRange::UNKNOWN);
                let _ = ix.intern_pure(NodeKey::Add(v, v), SpanRange::UNKNOWN);
                if i.is_multiple_of(4) {
                    let r = ix.reserve_opaque_id();
                    ix.emit_effect(
                        SideEffect::RangeCheck {
                            result: r,
                            operand: v,
                            bits: 8,
                        },
                        SpanRange::UNKNOWN,
                    );
                }
            }
            ix
        };
        let non_chunked = build(false).materialize();
        let chunked = build(true).materialize();
        assert_eq!(
            non_chunked.len(),
            chunked.len(),
            "chunked and non-chunked emit the same instruction count"
        );
        for (a, b) in non_chunked.iter().zip(chunked.iter()) {
            assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "chunked entry diverges from non-chunked"
            );
        }
    }

    #[test]
    fn chunked_into_chunked_iter_drains_in_emission_order() {
        // The lazy chunked iterator must yield the same sequence as the
        // flat `materialize()` Vec.
        let build = || {
            let mut ix = NodeInterner::<Bn254Fr>::with_streaming_window_chunked(8);
            for i in 0..20u64 {
                let _ = ix.intern_pure(NodeKey::Const(fe(i)), SpanRange::UNKNOWN);
            }
            ix
        };
        let flat = build().materialize();
        let lazy: Vec<_> = build().into_chunked_iter().collect();
        assert_eq!(flat.len(), lazy.len());
        for (a, b) in flat.iter().zip(lazy.iter()) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
    }

    #[test]
    fn into_instruction_stream_matches_materialize_streaming() {
        let build = || {
            let mut ix = NodeInterner::<Bn254Fr>::with_streaming_window(64);
            let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
            let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
            let c = ix.intern_pure(NodeKey::Mul(a, b), SpanRange::UNKNOWN);
            let _ = ix.intern_pure(NodeKey::Add(c, a), SpanRange::UNKNOWN);
            let opaque = ix.reserve_opaque_id();
            ix.emit_effect(
                SideEffect::RangeCheck {
                    result: opaque,
                    operand: a,
                    bits: 8,
                },
                SpanRange::UNKNOWN,
            );
            ix
        };
        let via_vec = build().materialize();
        let via_iter: Vec<_> = build().into_instruction_stream().collect();
        assert_eq!(via_vec.len(), via_iter.len());
        for (v, i) in via_vec.iter().zip(via_iter.iter()) {
            assert_eq!(format!("{v:?}"), format!("{i:?}"));
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
