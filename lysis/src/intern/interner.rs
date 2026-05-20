//! `NodeInterner<F>` — the hash-consing core.
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

use std::collections::{HashMap, HashSet, VecDeque};

use indexmap::IndexMap;
use memory::field::{Bn254Fr, FieldBackend, FieldElement};
use rustc_hash::FxBuildHasher;

use crate::intern::effect::{EffectId, SideEffect};
use crate::intern::hash::deterministic_hash;
use crate::intern::key::NodeKey;
use crate::intern::span::{SpanList, SpanRange};
use crate::intern::{InstructionKind, NodeId};

/// Cap on the eternal `Mul(Const, Const)` value-pair table. Sized from
/// Stage-1 probe data (10 distinct slots on the boss-fight) with a small
/// safety margin. Going past this fires the assert — that is the signal
/// to remeasure cardinality, not raise the cap silently.
pub(crate) const MUL_CC_TIER_CAP: usize = 64;

/// Per-chunk capacity for the chunked streaming-output layout. Sized
/// to land above glibc's mmap threshold (typically 128 KB to 64 MB) so
/// each chunk gets its own backing region the allocator returns
/// directly to the OS when the chunk drops. Smaller than the smallest
/// observed doubling target so the worst-case single allocation under
/// chunked mode is one chunk, not a multi-gigabyte Vec realloc.
pub(crate) const STREAMING_CHUNK_CAPACITY: usize = 1_000_000;

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
///
/// `nodes` uses `FxBuildHasher` for bucket placement — the IndexMap's
/// observable contract (insertion order, key equality) is hasher-
/// agnostic, so the cross-process determinism that matters is carried
/// by the cached `NodeMeta.hash` field (computed via
/// [`deterministic_hash`] / SipHash-2-4) rather than the bucket
/// distribution. Two independent runs assemble the map in the same
/// insertion order regardless of the bucket hasher.
#[derive(Debug, Clone)]
pub struct NodeInterner<F: FieldBackend = Bn254Fr> {
    pub(crate) nodes: IndexMap<NodeKey<F>, NodeMeta, FxBuildHasher>,
    pub(crate) effects: Vec<SideEffect>,
    pub(crate) node_spans: Vec<SpanList>,
    pub(crate) effect_spans: Vec<SpanList>,
    /// Global emission order: one entry per *new* pure insertion + one
    /// per side-effect. Dedup hits do not add to the timeline since
    /// the pure slot already appears. Unused under the streaming path
    /// (output is built incrementally on emission, no replay needed).
    pub(crate) timeline: Vec<Emission>,
    /// Monotonic across both pure and opaque ids. Never rewound.
    pub(crate) next_node_id: u32,
    /// When false, `node_spans` / `effect_spans` are never populated.
    /// `materialize` discards both channels unconditionally, so a
    /// consumer that only needs the flat instruction stream (no
    /// per-node source-span diagnostics) can skip accumulating them
    /// — on a fully-unrolled circuit that is one `SpanList` per
    /// interned node, a per-input-size memory cost for data that is
    /// then thrown away. Defaults to true; the span channels stay
    /// behaviourally identical for every existing caller.
    pub(crate) record_spans: bool,
    /// Eternal `Const(value) → NodeId` table. Always populated; on the
    /// streaming path this prevents Const dedup loss when a Const
    /// entry would otherwise have been evicted from `nodes`.
    pub(crate) const_table: HashMap<FieldElement<F>, NodeId>,
    /// Eternal `Mul(Const, Const) → NodeId` value-pair table. Keyed
    /// on symmetric-normalized Const-NodeIds (smaller index first);
    /// Const NodeIds are themselves stable per-value via [`Self::const_table`],
    /// so a NodeId pair is functionally equivalent to a value pair and
    /// avoids a NodeId-to-value reverse lookup on the hot path.
    /// Stage-1 probe measured ~10 distinct slots on the boss-fight;
    /// capped at [`MUL_CC_TIER_CAP`] with a hard assert.
    pub(crate) mul_cc_table: HashMap<(NodeId, NodeId), NodeId>,
    /// Streaming mode: when `Some`, the interner caps `nodes` at this
    /// many entries with FIFO eviction by insertion order, and emits
    /// the materialized stream incrementally into [`Self::streaming_output`]
    /// instead of accumulating a `timeline`. `None` keeps the legacy
    /// eager path byte-for-byte unchanged.
    pub(crate) window_size: Option<usize>,
    /// Incrementally-built materialized output Vec, populated only when
    /// `window_size.is_some()` AND `chunked == false`. Holds one entry
    /// per fresh pure insert + one per emitted effect, in emission order.
    pub(crate) streaming_output: Vec<InstructionKind<F>>,
    /// FIFO eviction order parallel to `nodes`. Populated only when
    /// streaming; `pop_front` returns the oldest key for `swap_remove`
    /// from `nodes` in O(1).
    pub(crate) eviction_queue: VecDeque<NodeKey<F>>,
    /// `NodeId`s that were minted for a `NodeKey::Const(_)` variant.
    /// Eternal — never evicted. Used to discriminate `Mul(Const, Const)`
    /// at `intern_pure` time without touching the `nodes` IndexMap
    /// (which may have evicted the Const entries already).
    pub(crate) const_nodes: HashSet<NodeId>,
    /// When `true`, the streaming-mode output is laid out as a sequence
    /// of fixed-capacity chunks (`streaming_chunks`) instead of a single
    /// doubling Vec. Each chunk allocates independently — the worst-case
    /// single allocation is one chunk, so the multi-gigabyte realloc
    /// transient that a doubling Vec triggers at very high instruction
    /// counts is eliminated. Used together with `window_size.is_some()`;
    /// when `false`, the eager `streaming_output` Vec is used (legacy
    /// behaviour).
    pub(crate) chunked: bool,
    /// Chunked-mode emission buffer. Populated only when `window_size.is_some()`
    /// AND `chunked == true`. Each inner Vec is pre-allocated with capacity
    /// [`Self::chunk_capacity`]; a new chunk is pushed once the current
    /// one fills.
    pub(crate) streaming_chunks: Vec<Vec<InstructionKind<F>>>,
    /// Per-chunk slot count used when allocating fresh chunks. Production
    /// uses [`STREAMING_CHUNK_CAPACITY`]; tests override via
    /// [`Self::with_streaming_window_chunked_capacity`] so the chunk-seal
    /// pop/allocate boundary can be exercised on small fixtures.
    pub(crate) chunk_capacity: usize,
}

impl<F: FieldBackend> Default for NodeInterner<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> NodeInterner<F> {
    /// Empty interner. Eager path: full hash-consing, no eviction,
    /// `materialize` replays the timeline at end. Byte-for-byte the
    /// historical behavior.
    pub fn new() -> Self {
        Self {
            nodes: IndexMap::with_hasher(FxBuildHasher),
            effects: Vec::new(),
            node_spans: Vec::new(),
            effect_spans: Vec::new(),
            timeline: Vec::new(),
            next_node_id: 0,
            record_spans: true,
            const_table: HashMap::new(),
            mul_cc_table: HashMap::new(),
            window_size: None,
            streaming_output: Vec::new(),
            eviction_queue: VecDeque::new(),
            const_nodes: HashSet::new(),
            chunked: false,
            streaming_chunks: Vec::new(),
            chunk_capacity: STREAMING_CHUNK_CAPACITY,
        }
    }

    /// Empty interner that never accumulates per-node span lists.
    /// Use when the only consumer is `materialize` (which discards
    /// the span channels): identical instruction stream, no span
    /// bookkeeping. Everything else — node ids, dedup, timeline,
    /// effect order — is byte-for-byte identical to [`Self::new`].
    pub fn without_span_tracking() -> Self {
        Self {
            record_spans: false,
            ..Self::new()
        }
    }

    /// Empty interner in **streaming mode**: the `nodes` IndexMap is
    /// capped at `window_size` entries with FIFO eviction by insertion
    /// order. Materialized output is built incrementally as fresh
    /// pure inserts + effects flow through. The `timeline` channel is
    /// not used. Const dedup is preserved across eviction by the
    /// eternal Const-value table; `Mul(Const, Const)` dedup likewise
    /// via the eternal value-pair table. Other long-range dedup hits
    /// past the window are forfeited — the materialized Vec is
    /// **functionally equivalent** (same post-O1 constraint count)
    /// but not byte-identical to the eager path.
    ///
    /// Spans are not populated; the trusted-replay opt-out is implicit.
    /// `window_size` of 0 is treated as "minimum useful window of 1"
    /// to avoid degenerate eviction-on-insert.
    pub fn with_streaming_window(window_size: usize) -> Self {
        let window_size = window_size.max(1);
        Self {
            record_spans: false,
            window_size: Some(window_size),
            ..Self::new()
        }
    }

    /// Streaming mode with chunked output storage. Same dedup contract
    /// as [`Self::with_streaming_window`] (Tier 1/2 eternal tables, Tier
    /// 3 windowed `nodes`, FIFO eviction). Differs only in the layout of
    /// the materialized emission buffer: instead of a single doubling
    /// Vec, each fresh push lands in the current chunk; when that chunk
    /// fills its capacity the interner allocates a fresh one. Worst-case
    /// single allocation is one chunk, eliminating multi-gigabyte Vec
    /// realloc transients on circuits with very high instruction counts.
    ///
    /// The materialized stream remains observable as a single
    /// `Vec<InstructionKind<F>>` via [`Self::materialize`] (which
    /// flattens chunks at the boundary), or via
    /// [`Self::into_chunked_iter`] which drains chunks lazily without
    /// the boundary Vec.
    pub fn with_streaming_window_chunked(window_size: usize) -> Self {
        Self::with_streaming_window_chunked_capacity(window_size, STREAMING_CHUNK_CAPACITY)
    }

    /// Chunked-streaming constructor with the per-chunk capacity
    /// overridable. The production path uses
    /// [`STREAMING_CHUNK_CAPACITY`] (~72 MB per chunk on `Bn254Fr`);
    /// tests dial it down to exercise the chunk-seal pop/allocate
    /// boundary without emitting a million instructions.
    pub fn with_streaming_window_chunked_capacity(
        window_size: usize,
        chunk_capacity: usize,
    ) -> Self {
        let window_size = window_size.max(1);
        let chunk_capacity = chunk_capacity.max(1);
        let mut me = Self::with_streaming_window(window_size);
        me.chunked = true;
        me.chunk_capacity = chunk_capacity;
        me.streaming_chunks.push(Vec::with_capacity(chunk_capacity));
        me
    }

    /// Push a freshly-emitted `InstructionKind<F>` into the streaming
    /// output. Chooses between the eager `Vec` and the chunked layout
    /// based on `self.chunked`. Caller has already verified
    /// `window_size.is_some()`.
    #[inline]
    pub(crate) fn push_streaming(&mut self, inst: InstructionKind<F>) {
        if self.chunked {
            // Allocate a fresh chunk if the current one is full or the
            // chunk vector is empty (defensive — the constructor seeds
            // the first chunk, but `Self::new()`-then-`chunked=true`
            // patches would not).
            if self
                .streaming_chunks
                .last()
                .map(|c| c.len() == c.capacity())
                .unwrap_or(true)
            {
                self.streaming_chunks
                    .push(Vec::with_capacity(self.chunk_capacity));
            }
            self.streaming_chunks
                .last_mut()
                .expect("last chunk seeded above")
                .push(inst);
        } else {
            self.streaming_output.push(inst);
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
        // Tier 3 (hot path): IndexMap lookup. Same as the historical
        // eager path; under streaming, hits also include all in-window
        // entries.
        if let Some((insertion_idx, _, meta)) = self.nodes.get_full(&key) {
            let id = meta.id;
            if let Some(list) = self.node_spans.get_mut(insertion_idx) {
                list.push_capped(span);
            }
            return id;
        }

        // Tier 1 (eternal Const): catches Const dedup after the entry
        // would have been evicted from `nodes`. The const_table itself
        // never evicts, so this is the long-range Const rescue.
        if let NodeKey::Const(v) = &key {
            if let Some(&id) = self.const_table.get(v) {
                return id;
            }
        }

        // Tier 2 (eternal Mul(Const, Const)): symmetric-normalized
        // value-pair lookup. Catches the dominant long-range Mul
        // dedup cohort once the original Mul entry has been evicted.
        // Both operand NodeIds must be in the eternal const_nodes set.
        if let NodeKey::Mul(a, b) = &key {
            if self.const_nodes.contains(a) && self.const_nodes.contains(b) {
                let pair = if a.index() <= b.index() {
                    (*a, *b)
                } else {
                    (*b, *a)
                };
                if let Some(&id) = self.mul_cc_table.get(&pair) {
                    return id;
                }
            }
        }

        // All tiers missed — fresh insert.
        let id = self.fresh_node_id();
        let hash = deterministic_hash(&key);
        let insertion_idx = self.nodes.len();

        // Populate eternal tiers BEFORE inserting into `nodes`, so a
        // future eviction of the Tier-3 entry still preserves the
        // long-range dedup path.
        match &key {
            NodeKey::Const(v) => {
                self.const_table.insert(*v, id);
                self.const_nodes.insert(id);
            }
            NodeKey::Mul(a, b) if self.const_nodes.contains(a) && self.const_nodes.contains(b) => {
                let pair = if a.index() <= b.index() {
                    (*a, *b)
                } else {
                    (*b, *a)
                };
                self.mul_cc_table.insert(pair, id);
                assert!(
                    self.mul_cc_table.len() <= MUL_CC_TIER_CAP,
                    "Mul(Const, Const) eternal tier exceeded the {} entry cap — \
                     re-measure cardinality (Stage-1 probe baseline = 10 distinct slots) \
                     before raising the cap",
                    MUL_CC_TIER_CAP,
                );
            }
            _ => {}
        }

        if let Some(cap) = self.window_size {
            // Streaming path: emit to output immediately, then insert
            // into `nodes`, then maybe evict the oldest entry.
            self.push_streaming(key.clone().into_instruction(id));
            self.eviction_queue.push_back(key.clone());
            self.nodes.insert(key, NodeMeta { id, hash });
            // record_spans is conventionally false in streaming mode,
            // but if a caller flips it we still mirror eager semantics.
            if self.record_spans {
                self.node_spans.push(SpanList::with_span(span));
            }
            while self.nodes.len() > cap {
                if let Some(old_key) = self.eviction_queue.pop_front() {
                    // Don't evict eternal-tier-tracked entries; they
                    // remain reachable via Tier 1/2 lookup but their
                    // hot-path Tier-3 slot is reclaimed.
                    let _removed = self.nodes.swap_remove(&old_key);
                    if !self.node_spans.is_empty() {
                        // node_spans is parallel to historical insertion
                        // order; under streaming we don't preserve that
                        // ordering once eviction starts, so this is a
                        // best-effort drop that keeps the Vec from
                        // growing unbounded when record_spans is set.
                        self.node_spans.pop();
                    }
                } else {
                    break;
                }
            }
        } else {
            // Eager path: byte-for-byte the historical behaviour.
            self.nodes.insert(key, NodeMeta { id, hash });
            if self.record_spans {
                debug_assert_eq!(self.node_spans.len(), insertion_idx);
                self.node_spans.push(SpanList::with_span(span));
            }
            self.timeline.push(Emission::Pure(insertion_idx));
        }

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
        if let Some(_cap) = self.window_size {
            // Streaming path: emit directly to output. The `effects`
            // Vec stays empty — the materialized output Vec already
            // carries every effect, no external consumer reads
            // `effects` field outside this crate (verified via grep),
            // and `effect_len()` returning 0 is fine for the streaming
            // path's contract (caller uses the output Vec). Skipping
            // the push releases the dominant non-node accumulator
            // (~1.1 GB on the boss-fight).
            self.push_streaming(SideEffect::into_instruction::<F>(effect));
        } else {
            self.effects.push(effect);
            if self.record_spans {
                self.effect_spans.push(SpanList::with_span(span));
            }
            self.timeline.push(Emission::Effect(eff_idx));
        }
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

    /// Pop and return every chunk that has filled to capacity. The
    /// currently-filling tail chunk (the last one in
    /// [`Self::streaming_chunks`]) stays behind so subsequent
    /// [`Self::push_streaming`] calls have somewhere to land. Caller
    /// drains each returned chunk and drops it, releasing its backing
    /// region to the OS.
    ///
    /// Returns an empty Vec when chunked streaming is not active, when
    /// no chunks exist yet, or when only the partially-filled tail
    /// chunk is present. Safe to call after every emission — the
    /// no-sealed-chunks fast path costs one len comparison.
    pub fn take_sealed_chunks(&mut self) -> Vec<Vec<InstructionKind<F>>> {
        if !self.chunked || self.streaming_chunks.len() <= 1 {
            return Vec::new();
        }
        let tail = self.streaming_chunks.pop().expect("len > 1 just verified");
        let sealed = std::mem::take(&mut self.streaming_chunks);
        self.streaming_chunks.push(tail);
        sealed
    }

    /// Drain every remaining chunk — sealed AND partial — leaving
    /// [`Self::streaming_chunks`] empty. Called once at end of
    /// execution to capture the final partial chunk before the
    /// interner is discarded.
    ///
    /// Returns an empty Vec when chunked streaming is not active.
    pub fn drain_all_chunks(&mut self) -> Vec<Vec<InstructionKind<F>>> {
        if !self.chunked {
            return Vec::new();
        }
        std::mem::take(&mut self.streaming_chunks)
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
}
