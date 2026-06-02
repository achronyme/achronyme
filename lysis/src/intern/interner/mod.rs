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

mod core;
mod streaming;

#[cfg(test)]
mod tests;

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
    pub(crate) next_node_id: u64,
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
}
