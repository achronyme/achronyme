use super::*;
use memory::field::FieldElement;

use crate::intern::span::SPAN_LIST_CAP;
use crate::intern::Visibility;

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

fn span(i: u32) -> SpanRange {
    SpanRange::new(i, i + 1)
}

// ------------------------------------------------------------------
// Pure channel: structural dedup.
// ------------------------------------------------------------------

#[test]
fn fresh_const_gets_id_zero() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let id = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    assert_eq!(id.index(), 0);
    assert_eq!(ix.pure_len(), 1);
}

#[test]
fn identical_keys_collapse_to_one_node() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(7)), SpanRange::UNKNOWN);
    let b = ix.intern_pure(NodeKey::Const(fe(7)), SpanRange::UNKNOWN);
    assert_eq!(a, b);
    assert_eq!(ix.pure_len(), 1);
}

#[test]
fn distinct_keys_get_distinct_ids() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    let c = ix.intern_pure(NodeKey::Add(a, b), SpanRange::UNKNOWN);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_eq!(ix.pure_len(), 3);
}

#[test]
fn add_operands_dedup_identity() {
    // Emit `a + b` twice — the two Adds collapse to one node.
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    let s1 = ix.intern_pure(NodeKey::Add(a, b), SpanRange::UNKNOWN);
    let s2 = ix.intern_pure(NodeKey::Add(a, b), SpanRange::UNKNOWN);
    assert_eq!(s1, s2);
    assert_eq!(ix.pure_len(), 3); // 2 Consts + 1 Add
}

// ------------------------------------------------------------------
// Span list accumulation.
// ------------------------------------------------------------------

#[test]
fn span_list_accumulates_on_dedup() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let id = ix.intern_pure(NodeKey::Const(fe(1)), span(0));
    let _ = ix.intern_pure(NodeKey::Const(fe(1)), span(10));
    let _ = ix.intern_pure(NodeKey::Const(fe(1)), span(20));
    let spans = ix.node_spans(id).unwrap();
    assert_eq!(spans.spans().len(), 3);
}

#[test]
fn span_list_respects_cap() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let id = ix.intern_pure(NodeKey::Const(fe(1)), span(0));
    for i in 1..30u32 {
        ix.intern_pure(NodeKey::Const(fe(1)), span(i));
    }
    let spans = ix.node_spans(id).unwrap();
    assert_eq!(spans.spans().len(), SPAN_LIST_CAP);
    assert!(spans.overflow_count() > 0);
}

// ------------------------------------------------------------------
// Effect channel: no dedup.
// ------------------------------------------------------------------

#[test]
fn identical_asserts_both_retained() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    let r1 = ix.reserve_opaque_id();
    let r2 = ix.reserve_opaque_id();
    let e1 = ix.emit_effect(
        SideEffect::AssertEq {
            result: r1,
            lhs: a,
            rhs: b,
            message: None,
        },
        SpanRange::UNKNOWN,
    );
    let e2 = ix.emit_effect(
        SideEffect::AssertEq {
            result: r2,
            lhs: a,
            rhs: b,
            message: None,
        },
        SpanRange::UNKNOWN,
    );
    assert_ne!(e1, e2);
    assert_eq!(ix.effect_len(), 2);
}

#[test]
fn reserve_opaque_id_does_not_appear_in_pure_table() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let opaque = ix.reserve_opaque_id();
    assert_eq!(ix.pure_len(), 0);
    assert!(ix.key_of(opaque).is_none());
    assert!(ix.hash_of(opaque).is_none());
}

// ------------------------------------------------------------------
// Counter monotonicity.
// ------------------------------------------------------------------

#[test]
fn opaque_and_pure_ids_share_counter() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let o = ix.reserve_opaque_id();
    let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    assert_eq!(a.index(), 0);
    assert_eq!(o.index(), 1);
    assert_eq!(b.index(), 2);
    assert_eq!(ix.total_node_ids(), 3);
}

// ------------------------------------------------------------------
// Lookup helpers.
// ------------------------------------------------------------------

#[test]
fn key_of_round_trips() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(42)), SpanRange::UNKNOWN);
    assert_eq!(ix.key_of(a), Some(&NodeKey::Const(fe(42))));
}

#[test]
fn hash_of_stable_across_lookups() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(7)), SpanRange::UNKNOWN);
    let h1 = ix.hash_of(a).unwrap();
    let h2 = ix.hash_of(a).unwrap();
    assert_eq!(h1, h2);
}

// ------------------------------------------------------------------
// Iteration.
// ------------------------------------------------------------------

#[test]
fn iter_pure_yields_in_insertion_order() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    let c = ix.intern_pure(NodeKey::Add(a, b), SpanRange::UNKNOWN);
    let ids: Vec<NodeId> = ix.iter_pure().map(|(id, _, _)| id).collect();
    assert_eq!(ids, vec![a, b, c]);
}

#[test]
fn iter_effects_yields_in_emission_order() {
    let mut ix = NodeInterner::<Bn254Fr>::new();
    let a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let out1 = ix.reserve_opaque_id();
    ix.emit_effect(
        SideEffect::Input {
            output: out1,
            name: "x".into(),
            visibility: Visibility::Public,
        },
        SpanRange::UNKNOWN,
    );
    let out2 = ix.reserve_opaque_id();
    ix.emit_effect(
        SideEffect::RangeCheck {
            result: out2,
            operand: a,
            bits: 8,
        },
        SpanRange::UNKNOWN,
    );
    let kinds: Vec<_> = ix
        .iter_effects()
        .map(|(_, eff)| std::mem::discriminant(eff))
        .collect();
    assert_eq!(kinds.len(), 2);
    assert_ne!(kinds[0], kinds[1]);
}

// ------------------------------------------------------------------
// Span-tracking opt-out preserves the materialized stream.
// ------------------------------------------------------------------

/// Build a representative sequence — pure dedup hit, distinct pure
/// nodes, and two side-effects — into the supplied interner.
fn build_sequence(ix: &mut NodeInterner<Bn254Fr>) {
    let a = ix.intern_pure(NodeKey::Const(fe(1)), span(1));
    let b = ix.intern_pure(NodeKey::Const(fe(2)), span(2));
    let _dup = ix.intern_pure(NodeKey::Const(fe(1)), span(3)); // dedup hit
    let s = ix.intern_pure(NodeKey::Add(a, b), span(4));
    let _ = ix.intern_pure(NodeKey::Mul(s, a), span(5));
    let r = ix.reserve_opaque_id();
    ix.emit_effect(
        SideEffect::RangeCheck {
            result: r,
            operand: s,
            bits: 8,
        },
        span(6),
    );
    let w = ix.reserve_opaque_id();
    ix.emit_effect(
        SideEffect::Input {
            output: w,
            name: "x".into(),
            visibility: Visibility::Public,
        },
        span(7),
    );
}

#[test]
fn without_span_tracking_materializes_identically_to_default() {
    let mut recorded = NodeInterner::<Bn254Fr>::new();
    let mut skipped = NodeInterner::<Bn254Fr>::without_span_tracking();
    build_sequence(&mut recorded);
    build_sequence(&mut skipped);

    // Same node/effect accounting either way.
    assert_eq!(recorded.pure_len(), skipped.pure_len());
    assert_eq!(recorded.effect_len(), skipped.effect_len());

    // The span-skipping interner accumulates no span lists; the
    // default one does. This is the memory invariant the opt-out
    // exists for.
    assert!(!recorded.node_spans.is_empty());
    assert!(!recorded.effect_spans.is_empty());
    assert!(skipped.node_spans.is_empty());
    assert!(skipped.effect_spans.is_empty());

    // …yet the flat instruction stream is identical, because
    // `materialize` discards both span channels. `InstructionKind`
    // is not `PartialEq`; compare via its `Debug` projection.
    assert_eq!(
        format!("{:?}", recorded.materialize()),
        format!("{:?}", skipped.materialize()),
    );
}

// ------------------------------------------------------------------
// Streaming-window path: 3-tier interner.
// ------------------------------------------------------------------

#[test]
fn streaming_with_huge_window_matches_eager_on_tiny_fixture() {
    // Window large enough that no eviction fires — pure machinery
    // pin: the streaming codepath produces a byte-identical
    // materialized Vec for inputs where forfeit is impossible.
    let mut eager = NodeInterner::<Bn254Fr>::new();
    let mut streaming = NodeInterner::<Bn254Fr>::with_streaming_window(1024);
    build_sequence(&mut eager);
    build_sequence(&mut streaming);

    assert_eq!(
        format!("{:?}", eager.materialize()),
        format!("{:?}", streaming.materialize()),
    );
}

#[test]
fn const_eternal_tier_survives_eviction() {
    // Window = 2. Insert Const(1), Const(2), then enough Mul nodes
    // to evict the Consts from the Tier-3 IndexMap. Re-intern
    // Const(1) — should still dedup to the original id via Tier 1.
    let mut ix = NodeInterner::<Bn254Fr>::with_streaming_window(2);
    let c1 = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let c2 = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);

    // Mul nodes whose operands aren't both Const — these go in
    // Tier 3 and trigger Const eviction once we exceed the cap.
    let _ = ix.intern_pure(NodeKey::Add(c1, c2), SpanRange::UNKNOWN);
    let _ = ix.intern_pure(NodeKey::Sub(c1, c2), SpanRange::UNKNOWN);
    let _ = ix.intern_pure(NodeKey::Neg(c1), SpanRange::UNKNOWN);

    // Re-intern Const(1) — Tier 1 must catch it.
    let c1_again = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    assert_eq!(c1, c1_again, "Const eternal tier must rescue evicted Const");
}

#[test]
fn mul_const_const_tier_survives_eviction() {
    // Window = 2. Insert two Consts + their Mul (caches into
    // Tier 2), then enough churn to evict the Mul from Tier 3.
    // Re-intern Mul(c1, c2) — should hit Tier 2.
    let mut ix = NodeInterner::<Bn254Fr>::with_streaming_window(2);
    let c1 = ix.intern_pure(NodeKey::Const(fe(7)), SpanRange::UNKNOWN);
    let c2 = ix.intern_pure(NodeKey::Const(fe(11)), SpanRange::UNKNOWN);
    let m = ix.intern_pure(NodeKey::Mul(c1, c2), SpanRange::UNKNOWN);

    // Force the Mul out of Tier 3 via churn.
    for i in 100u64..120u64 {
        let v = ix.intern_pure(NodeKey::Const(fe(i)), SpanRange::UNKNOWN);
        let _ = ix.intern_pure(NodeKey::Add(v, c1), SpanRange::UNKNOWN);
    }

    let m_again = ix.intern_pure(NodeKey::Mul(c1, c2), SpanRange::UNKNOWN);
    assert_eq!(
        m, m_again,
        "Mul(Const, Const) eternal tier must rescue evicted Mul"
    );
}

#[test]
fn streaming_emits_evicted_nodes_into_output() {
    // After eviction, the materialized Vec must still contain the
    // evicted nodes (they were emitted at fresh-insert time).
    let mut ix = NodeInterner::<Bn254Fr>::with_streaming_window(2);
    let _a = ix.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
    let _b = ix.intern_pure(NodeKey::Const(fe(2)), SpanRange::UNKNOWN);
    // Add a third Const → first two were already emitted, now evict one.
    let _c = ix.intern_pure(NodeKey::Const(fe(3)), SpanRange::UNKNOWN);

    let out = ix.materialize();
    assert_eq!(
        out.len(),
        3,
        "all three fresh inserts must appear in output"
    );
}
