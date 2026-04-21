//! Materialize a Lysis [`NodeInterner`] / [`InterningSink`] into the
//! canonical `Vec<Instruction<F>>` the R1CS backend consumes.
//!
//! This module is the "last mile" of the bridge started in
//! [`crate::prove_ir::lysis_bridge`]. The interner holds a
//! deduplicated DAG of `InstructionKind<F>`; the backend expects a
//! flat `Vec<Instruction<F>>`. The two steps combined — consume the
//! interner, flatten to the mirror enum, convert each node through
//! the bridge — are what the Phase 3 lifter uses to close the
//! `ProveIR-extended → ... → ir::Instruction<F>` pipeline.
//!
//! ## Memory handoff (RFC §5.6.1 route (c))
//!
//! The interner is consumed by value so its backing `IndexMap` +
//! span storage drop before we return. The intermediate
//! `Vec<InstructionKind<F>>` produced by [`lysis::NodeInterner::materialize`]
//! is `.into_iter()`-iterated into the final `Vec<Instruction<F>>`
//! — each `InstructionKind` drops the moment its `Instruction`
//! counterpart is produced, so peak-in-flight is O(1), not two
//! parallel Vecs.
//!
//! [`NodeInterner`]: lysis::NodeInterner
//! [`InterningSink`]: lysis::InterningSink

use memory::FieldBackend;

use crate::prove_ir::lysis_bridge::instruction_from_kind;
use crate::types::Instruction;

/// Consume a Lysis [`NodeInterner`] and produce a flat
/// `Vec<Instruction<F>>` ready for the R1CS backend.
pub fn materialize_interner<F: FieldBackend>(
    interner: lysis::NodeInterner<F>,
) -> Vec<Instruction<F>> {
    interner
        .materialize()
        .into_iter()
        .map(|kind| instruction_from_kind(&kind))
        .collect()
}

/// Consume a Lysis [`InterningSink`] and produce the flat IR. A
/// one-liner around [`materialize_interner`] that saves the caller
/// the `.into_interner()` call.
pub fn materialize_interning_sink<F: FieldBackend>(
    sink: lysis::InterningSink<F>,
) -> Vec<Instruction<F>> {
    materialize_interner(sink.into_interner())
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::types::SsaVar;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    // Helpers built on top of Lysis's ProgramBuilder + execute to drive
    // an InterningSink with known content.
    fn run_builder(
        build: impl FnOnce(&mut lysis::ProgramBuilder<Bn254Fr>),
    ) -> lysis::InterningSink<Bn254Fr> {
        let mut b = lysis::ProgramBuilder::<Bn254Fr>::new(lysis::FieldFamily::BnLike256);
        build(&mut b);
        let program = b.finish();
        let bytes = lysis::encode(&program);
        let decoded = lysis::decode::<Bn254Fr>(&bytes).expect("decode");
        lysis::bytecode::validate(&decoded, &lysis::LysisConfig::default()).expect("validate");
        let mut sink = lysis::InterningSink::<Bn254Fr>::new();
        lysis::execute(
            &decoded,
            &[],
            &lysis::LysisConfig::default(),
            &mut sink,
        )
        .expect("execute");
        sink
    }

    #[test]
    fn materialize_flattens_const_add() {
        let sink = run_builder(|b| {
            b.intern_field(fe(1));
            b.intern_field(fe(2));
            b.load_const(0, 0)
                .load_const(1, 1)
                .emit_add(2, 0, 1)
                .halt();
        });
        let instrs = materialize_interning_sink(sink);
        assert_eq!(instrs.len(), 3);
        assert!(matches!(instrs[0], Instruction::Const { .. }));
        assert!(matches!(instrs[1], Instruction::Const { .. }));
        assert!(matches!(instrs[2], Instruction::Add { .. }));
    }

    #[test]
    fn materialize_preserves_dedup_semantics() {
        // Emit Add(r0, r1) four times — dedup should collapse to one.
        let sink = run_builder(|b| {
            b.intern_field(fe(1));
            b.intern_field(fe(2));
            b.load_const(0, 0)
                .load_const(1, 1)
                .emit_add(2, 0, 1)
                .emit_add(3, 0, 1)
                .emit_add(4, 0, 1)
                .emit_add(5, 0, 1)
                .halt();
        });
        let instrs = materialize_interning_sink(sink);
        // 2 Consts + 1 Add (four dup collapsed)
        let add_count = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::Add { .. }))
            .count();
        assert_eq!(add_count, 1);
        assert_eq!(instrs.len(), 3);
    }

    #[test]
    fn materialize_preserves_side_effect_ordering() {
        let sink = run_builder(|b| {
            b.intern_field(fe(1));
            b.intern_field(fe(2));
            b.load_const(0, 0)
                .load_const(1, 1)
                .emit_assert_eq(0, 1)
                .emit_assert_eq(1, 0)
                .halt();
        });
        let instrs = materialize_interning_sink(sink);
        let asserts: Vec<_> = instrs
            .iter()
            .filter_map(|i| match i {
                Instruction::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        // Two distinct asserts, preserved in emission order.
        assert_eq!(asserts.len(), 2);
        assert_ne!(asserts[0], asserts[1]);
    }

    #[test]
    fn materialize_maps_ssa_vars_in_zero_based_order() {
        let sink = run_builder(|b| {
            b.intern_field(fe(7));
            b.load_const(0, 0).halt();
        });
        let instrs = materialize_interning_sink(sink);
        // The first (and only) node is Const(7) — SsaVar(0).
        assert_eq!(instrs.len(), 1);
        match &instrs[0] {
            Instruction::Const { result, value } => {
                assert_eq!(*result, SsaVar(0));
                assert_eq!(*value, fe(7));
            }
            _ => panic!("expected Const"),
        }
    }

    #[test]
    fn materialize_interner_direct_path() {
        // The lower-level API — operates on NodeInterner, not InterningSink.
        let mut interner = lysis::NodeInterner::<Bn254Fr>::new();
        let a = interner.intern_pure(
            lysis::NodeKey::Const(fe(1)),
            lysis::SpanRange::UNKNOWN,
        );
        let b = interner.intern_pure(
            lysis::NodeKey::Const(fe(2)),
            lysis::SpanRange::UNKNOWN,
        );
        let _s = interner.intern_pure(
            lysis::NodeKey::Add(a, b),
            lysis::SpanRange::UNKNOWN,
        );
        let instrs = materialize_interner(interner);
        assert_eq!(instrs.len(), 3);
    }
}
