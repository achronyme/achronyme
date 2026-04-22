//! `NodeInterner<F>` — the hash-consing core (RFC §5.1–5.3, §5.5).
//!
//! Two disjoint channels:
//!
//! - **Pure**: `nodes: IndexMap<NodeKey<F>, NodeMeta>`. Insertion
//!   order is topological — operands intern before their users, so
//!   iterating the map yields a valid emission schedule. Two
//!   textually-identical pure instructions collapse to one entry;
//!   further span inserts accumulate into the shared [`SpanList`].
//!
//! - **Effectful**: `effects: Vec<SideEffect>`. Never deduplicated.
//!   Preserves emission order. Diagnostics and materialization walk
//!   this in sequence.
//!
//! A single monotonic `u32` counter hands out [`NodeId`]s across
//! both channels: pure-node ids come from the first `intern_pure` of
//! a given key; opaque ids for side-effect outputs (`Input`,
//! `Decompose` bit results, `WitnessCall` outputs) are reserved
//! up-front via [`NodeInterner::reserve_opaque_id`] so the caller
//! can bind them into registers before calling `emit_effect`.

use indexmap::IndexMap;
use memory::field::{Bn254Fr, FieldBackend};

use crate::intern::effect::{EffectId, SideEffect};
use crate::intern::hash::{deterministic_hash, DeterministicBuildHasher};
use crate::intern::key::NodeKey;
use crate::intern::NodeId;
use crate::intern::span::{SpanList, SpanRange};

/// Metadata stored alongside each interned key. The cached hash lets
/// us answer "were these two nodes structurally equivalent?" in
/// constant time after the fact (useful for oracles / diagnostics).
#[derive(Debug, Clone, Copy)]
pub struct NodeMeta {
    pub id: NodeId,
    pub hash: u64,
}

/// Emission-order token for [`NodeInterner::timeline`]. Materialize
/// walks the timeline in order to produce a `Vec<InstructionKind<F>>`
/// whose operand dependencies never reference forward — essential
/// for side-effects like [`SideEffect::Decompose`] and
/// [`SideEffect::Input`] that define wires consumed by later pure
/// nodes.
#[derive(Debug, Clone, Copy)]
pub enum Emission {
    /// A new pure node was interned. Points at its insertion index
    /// in `nodes` (the IndexMap preserves it).
    Pure(usize),
    /// A side-effect was recorded. Points at its position in
    /// `effects`.
    Effect(usize),
}

/// Hash-consing table for pure nodes + ordered log of side-effects.
///
/// Fields are `pub(crate)` so the `materialize` submodule can
/// destructure by move during `materialize()`. External callers go
/// through the impl's methods; no field is exposed in the public API.
#[derive(Debug, Clone)]
pub struct NodeInterner<F: FieldBackend = Bn254Fr> {
    pub(crate) nodes: IndexMap<NodeKey<F>, NodeMeta, DeterministicBuildHasher>,
    pub(crate) effects: Vec<SideEffect>,
    pub(crate) node_spans: Vec<SpanList>,
    pub(crate) effect_spans: Vec<SpanList>,
    /// Global emission order: one entry per *new* pure insertion + one
    /// per side-effect. Dedup hits do not add to the timeline since
    /// the pure slot already appears.
    pub(crate) timeline: Vec<Emission>,
    /// Monotonic across both pure and opaque ids. Never rewound.
    pub(crate) next_node_id: u32,
}

impl<F: FieldBackend> Default for NodeInterner<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> NodeInterner<F> {
    /// Empty interner.
    pub fn new() -> Self {
        Self {
            nodes: IndexMap::with_hasher(DeterministicBuildHasher),
            effects: Vec::new(),
            node_spans: Vec::new(),
            effect_spans: Vec::new(),
            timeline: Vec::new(),
            next_node_id: 0,
        }
    }

    /// Intern a pure node. If an equivalent key is already present,
    /// the existing `NodeId` is returned and `span` is appended to
    /// its span list (subject to the [`crate::intern::span::SPAN_LIST_CAP`]).
    ///
    /// `node_spans[i]` is kept parallel to the `nodes` IndexMap, so
    /// the insertion index is the right cursor for both structures
    /// — not `NodeId.index()`, since opaque reservations between
    /// pure inserts would leave gaps in the latter.
    pub fn intern_pure(&mut self, key: NodeKey<F>, span: SpanRange) -> NodeId {
        if let Some((insertion_idx, _, meta)) = self.nodes.get_full(&key) {
            let id = meta.id;
            if let Some(list) = self.node_spans.get_mut(insertion_idx) {
                list.push_capped(span);
            }
            // Dedup hit: the pure node already appears on the timeline
            // from its first insertion. Don't push again.
            return id;
        }
        let id = self.fresh_node_id();
        let hash = deterministic_hash(&key);
        let insertion_idx = self.nodes.len();
        self.nodes.insert(key, NodeMeta { id, hash });
        debug_assert_eq!(self.node_spans.len(), insertion_idx);
        self.node_spans.push(SpanList::with_span(span));
        self.timeline.push(Emission::Pure(insertion_idx));
        id
    }

    /// Append a side-effect in emission order. `EffectId`s are
    /// assigned in insertion order starting from zero. Side-effects
    /// that define wires downstream pure nodes consume (e.g.
    /// [`SideEffect::Decompose`], [`SideEffect::Input`]) rely on the
    /// emission order being preserved through materialize — that's
    /// what the `timeline` log guarantees.
    pub fn emit_effect(&mut self, effect: SideEffect, span: SpanRange) -> EffectId {
        let eff_idx = self.effects.len();
        let eff_id = EffectId::from_zero_based(eff_idx);
        self.effects.push(effect);
        self.effect_spans.push(SpanList::with_span(span));
        self.timeline.push(Emission::Effect(eff_idx));
        eff_id
    }

    /// Hand out a fresh `NodeId` that is not interned. Used for
    /// side-effect outputs (e.g., `Input`'s new wire, `Decompose`'s
    /// per-bit results, `WitnessCall`'s outputs). These ids live in
    /// the same monotonic sequence as pure ids but have no entry in
    /// `nodes`, which is the signal to materialization that they
    /// were produced by an effect.
    pub fn reserve_opaque_id(&mut self) -> NodeId {
        // No span list for opaque ids — spans for side-effects live
        // in `effect_spans` instead, keyed by EffectId.
        self.fresh_node_id()
    }

    fn fresh_node_id(&mut self) -> NodeId {
        let id = NodeId::from_zero_based(self.next_node_id as usize);
        self.next_node_id = self
            .next_node_id
            .checked_add(1)
            .expect("NodeId counter overflows u32");
        id
    }

    /// Total unique pure nodes interned.
    #[inline]
    pub fn pure_len(&self) -> usize {
        self.nodes.len()
    }

    /// Total side-effects emitted.
    #[inline]
    pub fn effect_len(&self) -> usize {
        self.effects.len()
    }

    /// Total opaque NodeIds allocated (pure nodes + opaque reservations).
    #[inline]
    pub fn total_node_ids(&self) -> u32 {
        self.next_node_id
    }

    /// Look up the structural key for a pure `NodeId`. Returns `None`
    /// for opaque (side-effect-output) ids and for unknown ids.
    pub fn key_of(&self, id: NodeId) -> Option<&NodeKey<F>> {
        // Linear but nodes are insertion-ordered: the id is assigned
        // at insertion time, so iterating is O(n). Good enough for
        // diagnostics / post-hoc inspection; not on the hot path.
        self.nodes
            .iter()
            .find(|(_, meta)| meta.id == id)
            .map(|(k, _)| k)
    }

    /// Look up the cached hash for a pure node.
    pub fn hash_of(&self, id: NodeId) -> Option<u64> {
        self.nodes
            .iter()
            .find(|(_, meta)| meta.id == id)
            .map(|(_, meta)| meta.hash)
    }

    /// Span list attached to a pure `NodeId`. `None` for opaque ids.
    /// Linear scan — `O(pure_len)` — since we don't maintain a
    /// reverse id→insertion-index index. Off the hot path (used by
    /// diagnostics / materialize).
    pub fn node_spans(&self, id: NodeId) -> Option<&SpanList> {
        let idx = self.nodes.values().position(|m| m.id == id)?;
        self.node_spans.get(idx)
    }

    /// Span list attached to a side-effect.
    pub fn effect_spans(&self, eff: EffectId) -> Option<&SpanList> {
        self.effect_spans.get(eff.index())
    }

    /// Iterate pure nodes in insertion (= topological) order, yielding
    /// `(NodeId, &NodeKey, &NodeMeta)`. This is what
    /// [`crate::intern::materialize`] walks.
    pub fn iter_pure(&self) -> impl Iterator<Item = (NodeId, &NodeKey<F>, &NodeMeta)> {
        self.nodes.iter().map(|(key, meta)| (meta.id, key, meta))
    }

    /// Iterate side-effects in emission order.
    pub fn iter_effects(&self) -> impl Iterator<Item = (EffectId, &SideEffect)> {
        self.effects
            .iter()
            .enumerate()
            .map(|(i, eff)| (EffectId::from_zero_based(i), eff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::field::FieldElement;

    use crate::intern::Visibility;
    use crate::intern::span::SPAN_LIST_CAP;

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
}
