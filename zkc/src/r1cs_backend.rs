use crate::segmented_vec::SegmentedVec;
use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use constraints::r1cs_optimize::{R1CSOptimizeResult, SubstitutionMap};
use constraints::PoseidonParamsProvider;
use memory::field::PrimeId;
use memory::{Bn254Fr, FieldBackend, FieldElement};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// Per-call-site bool-check emission counters. Each tracks how many
// `b · (1 − b) = 0` constraints a specific code path has emitted
// since the last `reset_boolcheck_counters()` call. Useful when an
// optimisation diff or compiler-comparison probe wants to localise
// where bool-check shape constraints originate without re-running
// the entire pipeline with a debug build. All atomic; safe to
// snapshot or reset at any point.
pub static BC_RANGE_CHECK: AtomicU64 = AtomicU64::new(0);
pub static BC_NOT: AtomicU64 = AtomicU64::new(0);
pub static BC_AND_LHS: AtomicU64 = AtomicU64::new(0);
pub static BC_AND_RHS: AtomicU64 = AtomicU64::new(0);
pub static BC_OR_LHS: AtomicU64 = AtomicU64::new(0);
pub static BC_OR_RHS: AtomicU64 = AtomicU64::new(0);
pub static BC_ASSERT: AtomicU64 = AtomicU64::new(0);
pub static BC_DECOMPOSE: AtomicU64 = AtomicU64::new(0);
pub static BC_MUX_COND: AtomicU64 = AtomicU64::new(0);
pub static BC_ENFORCE_N_RANGE: AtomicU64 = AtomicU64::new(0);
pub static BC_IS_LT_VIA_BITS: AtomicU64 = AtomicU64::new(0);
pub static BC_DECOMPOSE_1BIT: AtomicU64 = AtomicU64::new(0);

pub fn snapshot_boolcheck_counters() -> [(&'static str, u64); 12] {
    [
        ("RangeCheck", BC_RANGE_CHECK.load(Ordering::Relaxed)),
        ("Not", BC_NOT.load(Ordering::Relaxed)),
        ("And.lhs", BC_AND_LHS.load(Ordering::Relaxed)),
        ("And.rhs", BC_AND_RHS.load(Ordering::Relaxed)),
        ("Or.lhs", BC_OR_LHS.load(Ordering::Relaxed)),
        ("Or.rhs", BC_OR_RHS.load(Ordering::Relaxed)),
        ("Assert", BC_ASSERT.load(Ordering::Relaxed)),
        ("Decompose", BC_DECOMPOSE.load(Ordering::Relaxed)),
        ("Mux.cond", BC_MUX_COND.load(Ordering::Relaxed)),
        (
            "enforce_n_range",
            BC_ENFORCE_N_RANGE.load(Ordering::Relaxed),
        ),
        ("is_lt_via_bits", BC_IS_LT_VIA_BITS.load(Ordering::Relaxed)),
        ("Decompose(1bit)", BC_DECOMPOSE_1BIT.load(Ordering::Relaxed)),
    ]
}

pub fn reset_boolcheck_counters() {
    BC_RANGE_CHECK.store(0, Ordering::Relaxed);
    BC_NOT.store(0, Ordering::Relaxed);
    BC_AND_LHS.store(0, Ordering::Relaxed);
    BC_AND_RHS.store(0, Ordering::Relaxed);
    BC_OR_LHS.store(0, Ordering::Relaxed);
    BC_OR_RHS.store(0, Ordering::Relaxed);
    BC_ASSERT.store(0, Ordering::Relaxed);
    BC_DECOMPOSE.store(0, Ordering::Relaxed);
    BC_MUX_COND.store(0, Ordering::Relaxed);
    BC_ENFORCE_N_RANGE.store(0, Ordering::Relaxed);
    BC_IS_LT_VIA_BITS.store(0, Ordering::Relaxed);
    BC_DECOMPOSE_1BIT.store(0, Ordering::Relaxed);
}

use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};

use crate::error::R1CSError;
use crate::r1cs_gadgets::power_of_two_generic;
use crate::witness::WitnessOp;

/// Maps an R1CS constraint back to the IR instruction that generated it.
#[derive(Debug, Clone)]
pub struct ConstraintOrigin {
    /// Index of the IR instruction in `IrProgram::instructions`.
    pub ir_index: usize,
    /// The SSA variable defined by the instruction.
    pub result_var: SsaVar,
}

/// Maximum LC term count before auto-materialization.
///
/// Without this, chains of Add/Sub (e.g. MDS in Poseidon partial rounds)
/// cause exponential LC growth: f(n) = 2·f(n-1)+1 ≈ 2^n terms.
/// Materializing keeps each LC bounded and prevents OOM on large circuits.
const LC_AUTO_MATERIALIZE_THRESHOLD: usize = 8;

/// Direct-indexed map from `SsaVar` to its cached `LinearCombination`.
///
/// The lysis chunk-drain pipeline issues `SsaVar.0` as a contiguous
/// monotonic counter starting at 0 (the dedup-canonical emission
/// order), so the address space has zero waste on the streaming path
/// where the boss-fight-class workloads land. Segmented
/// `Vec<Option<LinearCombination<F>>>` storage keeps that dense direct
/// index while bounding individual allocation requests; a single flat
/// Vec eventually has to double into multi-GiB reservations.
///
/// The non-streaming `compile_ir` / `compile_instructions` paths may
/// leave small `None` slack when an upstream DCE pass drops
/// instructions without renumbering the SSA ids, but the absolute
/// per-slot cost (24 B) is bounded by max(SsaVar.0) + 1, which on
/// those paths is small enough that the slack is not measurable.
#[derive(Debug, Clone)]
enum LcMapEntry<F: FieldBackend> {
    Zero,
    Variable(Variable),
    Terms(Vec<(Variable, FieldElement<F>)>),
}

impl<F: FieldBackend> LcMapEntry<F> {
    fn to_lc(&self) -> LinearCombination<F> {
        match self {
            Self::Zero => LinearCombination::zero(),
            Self::Variable(var) => LinearCombination::from_variable(*var),
            Self::Terms(terms) => {
                let mut lc = LinearCombination::zero();
                for (var, coeff) in terms {
                    lc.add_term(*var, *coeff);
                }
                lc
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LcMapShapeCounts {
    pub empty_slots: usize,
    pub zero_entries: usize,
    pub unit_variable_entries: usize,
    pub single_term_entries: usize,
    pub multi_term_entries: usize,
    pub stored_terms: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct R1CSRetainedStats {
    pub lc_empty_slots: usize,
    pub lc_zero_entries: usize,
    pub lc_unit_variable_entries: usize,
    pub lc_single_term_entries: usize,
    pub lc_multi_term_entries: usize,
    pub lc_stored_terms: usize,
    pub used_ssa_words: usize,
    pub proven_boolean_len: usize,
    pub bool_enforced_len: usize,
    pub range_bounds_len: usize,
    pub divmod_cache_len: usize,
    pub artik_program_intern_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum LcTag {
    Empty = 0,
    Zero = 1,
    Variable = 2,
    Terms = 3,
}

impl LcTag {
    fn from_slot(slot: u32) -> Self {
        match slot & 0b11 {
            0 => Self::Empty,
            1 => Self::Zero,
            2 => Self::Variable,
            3 => Self::Terms,
            _ => unreachable!("masked LC slot tag is always <= 3"),
        }
    }
}

#[derive(Debug, Clone)]
struct LcMapSegment<F: FieldBackend> {
    slots: Vec<u32>,
    term_starts: Vec<u32>,
    term_lens: Vec<u16>,
    terms: Vec<(Variable, FieldElement<F>)>,
}

impl<F: FieldBackend> LcMapSegment<F> {
    const TAG_BITS: u32 = 2;
    const MAX_PAYLOAD: usize = (1usize << (u32::BITS - Self::TAG_BITS)) - 1;

    fn new(segment_len: usize) -> Self {
        Self {
            slots: vec![0; segment_len],
            term_starts: Vec::new(),
            term_lens: Vec::new(),
            terms: Vec::new(),
        }
    }

    fn slot(tag: LcTag, payload: usize) -> u32 {
        assert!(
            payload <= Self::MAX_PAYLOAD,
            "R1CS LC map packed payload exceeded 30 bits"
        );
        ((payload as u32) << Self::TAG_BITS) | tag as u32
    }

    fn insert(&mut self, offset: usize, lc: LinearCombination<F>) {
        let terms = lc.into_terms();
        match terms.as_slice() {
            [] => {
                self.slots[offset] = Self::slot(LcTag::Zero, 0);
            }
            [(var, coeff)] if *coeff == FieldElement::<F>::one() => {
                self.slots[offset] = Self::slot(LcTag::Variable, var.0);
            }
            _ => {
                let len =
                    u16::try_from(terms.len()).expect("R1CS LC map entry exceeded u16 term length");
                let start = self.terms.len();
                let entry_idx = self.term_starts.len();
                self.terms.extend(terms);
                self.term_starts.push(
                    u32::try_from(start).expect("R1CS LC map term arena exceeded u32 payload"),
                );
                self.term_lens.push(len);
                self.slots[offset] = Self::slot(LcTag::Terms, entry_idx);
            }
        }
    }

    fn get(&self, offset: usize) -> Option<LcMapEntry<F>> {
        let slot = self.slots.get(offset).copied()?;
        let payload = (slot >> Self::TAG_BITS) as usize;
        match LcTag::from_slot(slot) {
            LcTag::Empty => None,
            LcTag::Zero => Some(LcMapEntry::Zero),
            LcTag::Variable => Some(LcMapEntry::Variable(Variable(payload))),
            LcTag::Terms => {
                let start = self.term_starts[payload] as usize;
                let len = self.term_lens[payload] as usize;
                Some(LcMapEntry::Terms(self.terms[start..start + len].to_vec()))
            }
        }
    }

    fn shape_counts(&self, counts: &mut LcMapShapeCounts) {
        for slot in &self.slots {
            let payload = (*slot >> Self::TAG_BITS) as usize;
            match LcTag::from_slot(*slot) {
                LcTag::Empty => counts.empty_slots += 1,
                LcTag::Zero => counts.zero_entries += 1,
                LcTag::Variable => counts.unit_variable_entries += 1,
                LcTag::Terms => {
                    let len = self.term_lens[payload] as usize;
                    if len == 1 {
                        counts.single_term_entries += 1;
                    } else {
                        counts.multi_term_entries += 1;
                    }
                    counts.stored_terms += len;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct LcMap<F: FieldBackend> {
    segments: Vec<Option<LcMapSegment<F>>>,
    segment_len: usize,
    keep_last_vars: Option<usize>,
    keep_prefix_vars: usize,
    min_retained_idx: usize,
    pruned_segment_count: usize,
}

impl<F: FieldBackend> LcMap<F> {
    const DEFAULT_SEGMENT_LEN: usize = 1 << 16;

    fn new() -> Self {
        Self::with_segment_len(Self::DEFAULT_SEGMENT_LEN)
    }

    fn with_segment_len(segment_len: usize) -> Self {
        assert!(segment_len > 0, "lc_map segment length must be positive");
        Self {
            segments: Vec::new(),
            segment_len,
            keep_last_vars: None,
            keep_prefix_vars: 0,
            min_retained_idx: 0,
            pruned_segment_count: 0,
        }
    }

    fn set_keep_last_vars(&mut self, keep_last_vars: Option<usize>) {
        self.keep_last_vars = keep_last_vars;
    }

    fn set_keep_prefix_vars(&mut self, keep_prefix_vars: usize) {
        self.keep_prefix_vars = keep_prefix_vars;
    }

    fn insert(&mut self, var: SsaVar, mut lc: LinearCombination<F>) {
        // LCs reach this cache after incremental `add_term` calls,
        // which leave the term vec at the next power-of-two doubling
        // step. The shape histogram on boss-fight-class workloads
        // shows ~49% capacity slack steady-state because the dominant
        // case is a 1-term LC sitting in a cap-2 vec. Trim before
        // storing so the long-lived heap footprint matches the active
        // term count. Gated on `capacity > len` to skip the allocator
        // round-trip on already-tight LCs (empty `Vec::new` plus any
        // LC built via `vec![..]` macros).
        if lc.terms().len() < lc.terms_capacity() {
            lc.shrink_to_fit();
        }
        let idx = var.0 as usize;
        let segment_idx = idx / self.segment_len;
        let offset = idx % self.segment_len;
        while segment_idx >= self.segments.len() {
            self.segments.push(None);
        }
        let segment =
            self.segments[segment_idx].get_or_insert_with(|| LcMapSegment::new(self.segment_len));
        segment.insert(offset, lc);
        self.prune_old_segments(idx);
    }

    fn get(&self, var: &SsaVar) -> Option<LinearCombination<F>> {
        let idx = var.0 as usize;
        if idx >= self.keep_prefix_vars && idx < self.min_retained_idx {
            return None;
        }
        let segment_idx = idx / self.segment_len;
        let offset = idx % self.segment_len;
        self.segments
            .get(segment_idx)
            .and_then(Option::as_ref)
            .and_then(|segment| segment.get(offset))
            .map(|entry| entry.to_lc())
    }

    #[cfg(test)]
    fn get_entry(&self, var: &SsaVar) -> Option<LcMapEntry<F>> {
        let idx = var.0 as usize;
        if idx >= self.keep_prefix_vars && idx < self.min_retained_idx {
            return None;
        }
        let segment_idx = idx / self.segment_len;
        let offset = idx % self.segment_len;
        self.segments
            .get(segment_idx)
            .and_then(Option::as_ref)
            .and_then(|segment| segment.get(offset))
    }

    fn clear(&mut self) {
        self.segments.clear();
        self.min_retained_idx = 0;
        self.pruned_segment_count = 0;
    }

    fn shape_counts(&self) -> LcMapShapeCounts {
        let mut counts = LcMapShapeCounts::default();
        for segment in &self.segments {
            if let Some(segment) = segment {
                segment.shape_counts(&mut counts);
            }
        }
        counts
    }

    #[cfg(test)]
    fn slot_count(&self) -> usize {
        self.segments
            .iter()
            .filter_map(Option::as_ref)
            .map(|segment| segment.slots.len())
            .sum()
    }

    #[cfg(test)]
    fn allocated_segment_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|segment| segment.is_some())
            .count()
    }

    fn prune_old_segments(&mut self, newest_idx: usize) {
        let Some(keep_last_vars) = self.keep_last_vars else {
            return;
        };
        let min_retained_idx = newest_idx
            .saturating_add(1)
            .saturating_sub(keep_last_vars)
            .max(self.keep_prefix_vars);
        if min_retained_idx <= self.min_retained_idx {
            return;
        }
        self.min_retained_idx = min_retained_idx;

        let drop_before_segment = min_retained_idx / self.segment_len;
        let protected_segment_count = self.keep_prefix_vars.div_ceil(self.segment_len);
        let first_segment_to_drop = self.pruned_segment_count.max(protected_segment_count);
        if drop_before_segment <= first_segment_to_drop {
            return;
        }
        for segment in self
            .segments
            .iter_mut()
            .take(drop_before_segment)
            .skip(first_segment_to_drop)
        {
            *segment = None;
        }
        self.pruned_segment_count = drop_before_segment;
    }
}

#[derive(Debug, Clone)]
struct UsedSsaSet {
    segments: Vec<Option<Vec<usize>>>,
    segment_bits: usize,
    keep_last_vars: Option<usize>,
    keep_prefix_vars: usize,
    min_retained_idx: usize,
    pruned_segment_count: usize,
}

impl UsedSsaSet {
    const DEFAULT_SEGMENT_BITS: usize = 1 << 20;

    fn new() -> Self {
        Self::with_segment_bits(Self::DEFAULT_SEGMENT_BITS)
    }

    fn with_segment_bits(segment_bits: usize) -> Self {
        assert!(segment_bits > 0, "used SSA segment bits must be positive");
        assert!(
            segment_bits % usize::BITS as usize == 0,
            "used SSA segment bits must align to word size"
        );
        Self {
            segments: Vec::new(),
            segment_bits,
            keep_last_vars: None,
            keep_prefix_vars: 0,
            min_retained_idx: 0,
            pruned_segment_count: 0,
        }
    }

    fn set_keep_last_vars(&mut self, keep_last_vars: Option<usize>) {
        self.keep_last_vars = keep_last_vars;
    }

    fn set_keep_prefix_vars(&mut self, keep_prefix_vars: usize) {
        self.keep_prefix_vars = keep_prefix_vars;
    }

    fn mark(&mut self, var: SsaVar) {
        let idx = var.0 as usize;
        let segment_idx = idx / self.segment_bits;
        let offset = idx % self.segment_bits;
        let word = offset / usize::BITS as usize;
        let bit = offset % usize::BITS as usize;
        while segment_idx >= self.segments.len() {
            self.segments.push(None);
        }
        let words_per_segment = self.segment_bits / usize::BITS as usize;
        let segment = self.segments[segment_idx].get_or_insert_with(|| vec![0; words_per_segment]);
        segment[word] |= 1usize << bit;
        self.prune_old_segments(idx);
    }

    fn contains(&self, var: SsaVar) -> bool {
        let idx = var.0 as usize;
        if idx >= self.keep_prefix_vars && idx < self.min_retained_idx {
            return false;
        }
        let segment_idx = idx / self.segment_bits;
        let offset = idx % self.segment_bits;
        let word = offset / usize::BITS as usize;
        let bit = offset % usize::BITS as usize;
        self.segments
            .get(segment_idx)
            .and_then(Option::as_ref)
            .and_then(|segment| segment.get(word))
            .map(|bits| (bits & (1usize << bit)) != 0)
            .unwrap_or(false)
    }

    fn clear(&mut self) {
        self.segments.clear();
        self.min_retained_idx = 0;
        self.pruned_segment_count = 0;
    }

    fn word_count(&self) -> usize {
        self.segments
            .iter()
            .filter_map(Option::as_ref)
            .map(Vec::len)
            .sum()
    }

    fn prune_old_segments(&mut self, newest_idx: usize) {
        let Some(keep_last) = self.keep_last_vars else {
            return;
        };
        if newest_idx + 1 <= keep_last {
            return;
        }
        let min_retained_idx = (newest_idx + 1 - keep_last).max(self.keep_prefix_vars);
        if min_retained_idx <= self.min_retained_idx {
            return;
        }
        self.min_retained_idx = min_retained_idx;

        let drop_before_segment = min_retained_idx / self.segment_bits;
        let protected_segment_count = self.keep_prefix_vars.div_ceil(self.segment_bits);
        let first_segment_to_drop = self.pruned_segment_count.max(protected_segment_count);
        if drop_before_segment <= first_segment_to_drop {
            return;
        }
        for segment in self
            .segments
            .iter_mut()
            .take(drop_before_segment)
            .skip(first_segment_to_drop)
        {
            *segment = None;
        }
        self.pruned_segment_count = drop_before_segment;
    }
}

/// Compiles an Achronyme SSA IR program into an R1CS constraint system.
///
/// The R1CSCompiler walks IR instructions and emits R1CS constraints.
/// Each expression maps to a `LinearCombination`, and only multiplications /
/// materializations generate actual constraints.
pub struct R1CSCompiler<F: FieldBackend = Bn254Fr> {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem<F>,
    /// Declared variables: maps `public`/`witness` names → allocated R1CS wire.
    /// Only contains explicitly declared circuit inputs (not `let` bindings).
    pub bindings: HashMap<String, Variable>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    pub(crate) poseidon_params: Option<PoseidonParams<F>>,
    /// Witness generation trace: records each intermediate variable allocation.
    ///
    /// Stored in a [`SegmentedVec`] rather than a flat `Vec` so the
    /// container never issues a single allocation larger than
    /// `SegmentedVec::DEFAULT_SEGMENT_MAX * size_of::<WitnessOp<F>>()`
    /// (~64 MB at the current op layout). Boss-fight-class circuits
    /// emitting millions of witness ops would otherwise trigger a 1+ GiB
    /// `Vec::push` doubling request mid-stream that constrained sandboxes
    /// reject.
    pub witness_ops: SegmentedVec<WitnessOp<F>>,
    /// Prime field for this compilation.
    /// Determines the default bit width for range checks and comparisons.
    pub prime_id: PrimeId,
    /// SSA variables proven to be boolean by bool_prop analysis.
    /// Boolean enforcement constraints are skipped for these.
    proven_boolean: std::collections::HashSet<ir::types::SsaVar>,
    /// SSA variables for which boolean enforcement (v * (1-v) = 0) has already
    /// been emitted. Avoids duplicate constraints when the same condition
    /// is used in multiple Mux/And/Or instructions.
    bool_enforced: std::collections::HashSet<ir::types::SsaVar>,
    /// Maps each R1CS constraint index to the IR instruction that generated it.
    /// Built during `compile_ir`, parallel to `cs.constraints()`. Skipped when
    /// `track_constraint_origins` is false (see `R1CSCompiler::new_lean`).
    pub constraint_origins: Vec<ConstraintOrigin>,
    /// Toggle for `constraint_origins` population. Defaults to `true` so the
    /// inspector / CLI provenance readers keep working. Setting it to `false`
    /// (via `new_lean`) skips the per-constraint origin push on the hot
    /// emission path, freeing ~16 B per emitted constraint plus Vec capacity
    /// tail — material on circuits emitting tens of millions of constraints.
    track_constraint_origins: bool,
    /// Toggle for retaining input-name metadata while compiling IR inputs.
    ///
    /// Normal compilers keep the `bindings`, `public_inputs`, and `witnesses`
    /// name tables for witness lookup, inspectors, and CLI consumers. The
    /// lean boss-fight path only needs wire allocation and constraints; keeping
    /// one `String` plus one hash entry for every synthetic lysis witness slot
    /// is pure retention overhead there.
    track_input_metadata: bool,
    /// Lean-only forward collapse for `AssertEq` assignments whose lhs is a
    /// fresh private wire. The default compiler keeps the historical one
    /// constraint per assert surface; the boss-fight lean path uses this to
    /// avoid retaining eliminate-before-use linear constraints.
    forward_assert_eq_collapse: bool,
    /// Emit multi-term LC products directly instead of first materializing each
    /// operand into a fresh wire.
    ///
    /// The default path materializes `LC_a` and `LC_b`, emits linear
    /// constraints for those fresh wires, then relies on O1 to substitute them
    /// away. This mode emits the post-substitution quadratic shape directly:
    /// `LC_a * LC_b = out`.
    pub(crate) direct_linear_mul: bool,
    /// Whether to retain witness-generation operations.
    ///
    /// Compile-only benchmarks and exporters that only need the constraint
    /// shape can disable this log to avoid retaining one witness operation per
    /// intermediate wire. Normal proving paths leave it enabled.
    pub(crate) record_witness_ops: bool,
    /// Variable substitution map from R1CS linear constraint elimination.
    /// Set by `optimize_r1cs()`. Used by witness generation to compute
    /// values for substituted-away wires.
    pub substitution_map: Option<SubstitutionMap<F>>,
    /// Lookup cache: SSA variable → its `LinearCombination`. Populated as the
    /// compiler walks the IR instruction stream. Reset at the start of
    /// every `compile_ir` call.
    lc_map: LcMap<F>,
    /// Optional upper bound for term count retained in `lc_map`.
    ///
    /// When set, cached non-constant LCs longer than this limit are
    /// materialized into a fresh wire before insertion, so future lookups see
    /// a one-variable LC instead of keeping the full term list alive. The
    /// default compiler leaves this unset because materialization emits extra
    /// linear constraints; compile-only sizing probes can enable it to trade
    /// constraint count for bounded resident memory.
    lc_cache_term_limit: Option<usize>,
    /// Dense bitset over `SsaVar.0`: set once an SSA value has been consumed
    /// by any later instruction. Used by the forward `AssertEq` collapse to
    /// substitute fresh private assignment targets without keeping a global
    /// substitution map.
    used_ssa: UsedSsaSet,
    /// Proven bit-width bounds from `RangeCheck`, used by `IsLt`/`IsLe`.
    range_bounds: HashMap<SsaVar, u32>,
    /// Cached divmod gadgets: `(lhs, rhs, max_bits) → (q_lc, r_lc)`.
    /// When `IntDiv` and `IntMod` use the same operands, the second reuses
    /// the cached result instead of emitting duplicate constraints.
    #[allow(clippy::type_complexity)]
    divmod_cache: HashMap<(SsaVar, SsaVar, u32), (LinearCombination<F>, LinearCombination<F>)>,
    /// Content-hash intern table for Artik bytecode payloads.
    /// Holds `Arc<[u8]>` so identical payloads emitted at multiple
    /// `WitnessCall` sites share one heap allocation. A flat `Vec`
    /// (not `HashMap`) is the right shape here: a single compilation
    /// typically yields a handful of unique templates, and linear scan
    /// over a cache-resident `Vec<(u64, Arc<[u8]>)>` beats `HashMap`
    /// probing for that cardinality — no empty-slot overhead, fully
    /// deterministic insertion order. The secondary slice equality
    /// check on a `u64` hash hit is mandatory: a 64-bit collision
    /// (astronomically unlikely but not impossible) would otherwise
    /// alias distinct programs to the same `Arc` and corrupt witness
    /// execution.
    artik_program_intern: Vec<(u64, Arc<[u8]>)>,
}

impl<F: FieldBackend> Default for R1CSCompiler<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> R1CSCompiler<F> {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            prime_id: PrimeId::Bn254,
            poseidon_params: None,
            witness_ops: SegmentedVec::new(),
            proven_boolean: std::collections::HashSet::new(),
            bool_enforced: std::collections::HashSet::new(),
            constraint_origins: Vec::new(),
            track_constraint_origins: true,
            track_input_metadata: true,
            forward_assert_eq_collapse: false,
            direct_linear_mul: false,
            record_witness_ops: true,
            substitution_map: None,
            lc_map: LcMap::new(),
            lc_cache_term_limit: None,
            used_ssa: UsedSsaSet::new(),
            range_bounds: HashMap::new(),
            divmod_cache: HashMap::new(),
            artik_program_intern: Vec::new(),
        }
    }

    /// Create an R1CS compiler that skips per-constraint origin tracking.
    ///
    /// `constraint_origins` is left empty across the full emission. Callers
    /// that don't need IR-instruction provenance (high-volume circuits that
    /// only run prove/verify, never inspect) save ~16 B per emitted
    /// constraint plus the parallel Vec's capacity-tail. On boss-fight-class
    /// circuits emitting ~10M constraints this is hundreds of MB of peak
    /// RSS.
    ///
    /// Note that `optimize_r1cs*` already clears `constraint_origins` after
    /// linear substitution rebuilds the constraint vec, so downstream
    /// readers must already tolerate an empty origins vec — `new_lean`
    /// extends that tolerance window to before the optimize step too.
    pub fn new_lean() -> Self {
        let mut c = Self::new();
        c.track_constraint_origins = false;
        c.track_input_metadata = false;
        c.forward_assert_eq_collapse = true;
        c
    }

    /// Create a compiler that folds linear-constraint elimination into
    /// emission (incremental collapse). The underlying constraint system
    /// never materializes the unoptimized set: each linear constraint is
    /// absorbed into a substitution map at `enforce` time, so
    /// `cs.num_constraints()` tracks the post-elimination survivor count
    /// rather than the pre-optimization total. Builds on `new_lean` for
    /// origin tracking and fresh-private assert collapse, but restores input
    /// metadata so normal witness generation by declared names keeps working.
    /// After compilation, recover the substitution map for witness fixup via
    /// `cs.take_collapse_substitution_map()`.
    pub fn new_incremental() -> Self {
        let mut c = Self::new_lean();
        c.track_input_metadata = true;
        c.cs.enable_incremental_collapse();
        c
    }

    /// Create a lean compiler that emits multi-term LC products directly.
    ///
    /// This avoids building the linear materialization constraints that O1
    /// would later eliminate, so the resident constraint set tracks a shape
    /// closer to post-O1 during emission.
    pub fn new_direct_linear_mul() -> Self {
        let mut c = Self::new_lean();
        c.direct_linear_mul = true;
        c
    }

    /// Create a lean compile-only compiler that skips witness-op and
    /// constraint-row retention.
    ///
    /// Constraint and wire counts remain exact, but callers cannot serialize,
    /// optimize, prove, or verify from the returned in-memory rows. This mode
    /// is for sizing and compile-through probes that only need to exercise the
    /// emitter.
    pub fn new_compile_only_direct_linear_mul() -> Self {
        let mut c = Self::new_direct_linear_mul();
        c.record_witness_ops = false;
        c.cs.disable_constraint_retention();
        match std::env::var("ACH_R1CS_COMPILE_ONLY_COLLAPSE").as_deref() {
            Ok("1") | Ok("true") | Ok("full") => c.cs.enable_incremental_collapse(),
            Ok("count") | Ok("count-only") | Ok("discard") => {
                c.cs.enable_incremental_collapse_count_only();
            }
            _ => {}
        }
        if let Some(limit) = std::env::var("ACH_R1CS_LC_CACHE_TERM_LIMIT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            c.lc_cache_term_limit = Some(limit);
        }
        if let Some(keep_last) = std::env::var("ACH_R1CS_LC_MAP_KEEP_LAST")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
        {
            c.lc_map.set_keep_last_vars(Some(keep_last));
            c.used_ssa.set_keep_last_vars(Some(keep_last));
        }
        if let Some(keep_prefix) = std::env::var("ACH_R1CS_LC_MAP_KEEP_PREFIX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
        {
            c.lc_map.set_keep_prefix_vars(keep_prefix);
            c.used_ssa.set_keep_prefix_vars(keep_prefix);
        }
        c
    }

    pub fn lc_map_shape_counts(&self) -> LcMapShapeCounts {
        self.lc_map.shape_counts()
    }

    pub fn retained_stats(&self) -> R1CSRetainedStats {
        let shapes = self.lc_map.shape_counts();
        R1CSRetainedStats {
            lc_empty_slots: shapes.empty_slots,
            lc_zero_entries: shapes.zero_entries,
            lc_unit_variable_entries: shapes.unit_variable_entries,
            lc_single_term_entries: shapes.single_term_entries,
            lc_multi_term_entries: shapes.multi_term_entries,
            lc_stored_terms: shapes.stored_terms,
            used_ssa_words: self.used_ssa.word_count(),
            proven_boolean_len: self.proven_boolean.len(),
            bool_enforced_len: self.bool_enforced.len(),
            range_bounds_len: self.range_bounds.len(),
            divmod_cache_len: self.divmod_cache.len(),
            artik_program_intern_len: self.artik_program_intern.len(),
        }
    }

    fn cache_lc(&mut self, result: SsaVar, lc: LinearCombination<F>) {
        let lc = match self.lc_cache_term_limit {
            Some(limit)
                if lc.terms().len() > limit
                    && lc.as_single_variable().is_none()
                    && lc.constant_value().is_none() =>
            {
                LinearCombination::from_variable(self.materialize_lc(&lc))
            }
            _ => lc,
        };
        self.lc_map.insert(result, lc);
    }

    pub(crate) fn push_witness_op(&mut self, op: WitnessOp<F>) {
        if self.record_witness_ops {
            self.witness_ops.push(op);
        }
    }

    /// Intern an Artik bytecode payload. Returns an `Arc<[u8]>` shared
    /// with prior emissions whose `program_bytes` are byte-identical;
    /// otherwise allocates a fresh `Arc` and registers it.
    ///
    /// Linear scan is intentional — see the field doc on
    /// `artik_program_intern` for the cardinality reasoning.
    fn intern_artik_program(&mut self, bytes: &[u8]) -> Arc<[u8]> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let digest = hasher.finish();

        for (h, arc) in self.artik_program_intern.iter() {
            if *h == digest && arc.as_ref() == bytes {
                return arc.clone();
            }
        }
        let arc: Arc<[u8]> = Arc::from(bytes);
        self.artik_program_intern.push((digest, arc.clone()));
        arc
    }

    /// Number of unique Artik bytecode payloads currently interned.
    /// Test-only accessor — production code has no reason to inspect
    /// the intern table.
    #[cfg(test)]
    pub(crate) fn artik_program_intern_len(&self) -> usize {
        self.artik_program_intern.len()
    }

    /// Look up the cached `LinearCombination` for `var`. Returns an error if
    /// the variable was referenced before it was defined — a structural
    /// invariant of SSA form that the walker relies on.
    fn lookup_lc(&mut self, var: &SsaVar) -> Result<LinearCombination<F>, R1CSError> {
        self.mark_ssa_used(*var);
        self.lookup_lc_untracked(var)
    }

    fn lookup_lc_untracked(&self, var: &SsaVar) -> Result<LinearCombination<F>, R1CSError> {
        self.lc_map.get(var).ok_or_else(|| {
            R1CSError::UnsupportedOperation(format!("undefined SSA variable {:?}", var), None)
        })
    }

    fn mark_ssa_used(&mut self, var: SsaVar) {
        self.used_ssa.mark(var);
    }

    fn is_ssa_used(&self, var: SsaVar) -> bool {
        self.used_ssa.contains(var)
    }

    /// Set the proven-boolean set from bool_prop analysis.
    /// Variables in this set skip redundant boolean enforcement constraints.
    pub fn set_proven_boolean(&mut self, set: std::collections::HashSet<ir::types::SsaVar>) {
        self.proven_boolean = set;
    }

    /// Run linear constraint elimination on the compiled R1CS.
    ///
    /// Must be called after `compile_ir()` / `compile_ir_with_witness()`.
    /// Identifies constraints of the form `k * LC = LC` (linear, no real
    /// multiplication) and substitutes one wire with the LC, eliminating
    /// the constraint. Runs to fixpoint.
    ///
    /// Also updates `witness_ops` (removes ops for substituted targets,
    /// applies substitutions to source LCs) and `constraint_origins`.
    ///
    /// The substitution map is stored for witness post-fixup.
    pub fn optimize_r1cs(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_linear();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Install a finalize pass's substitution map: compose it with the
    /// incremental-collapse map (when collapse was enabled during
    /// emission), apply the result to `witness_ops`, and store it for
    /// witness reconstruction.
    ///
    /// When collapse is disabled (`take_collapse_substitution_map` →
    /// `None`) this is exactly the legacy path: store `finalize_subs`
    /// verbatim. When collapse ran, the finalize pass operated on the
    /// collapse survivors, so its map alone reconstructs only the wires
    /// *it* eliminated; the collapse map must be composed in (collapse
    /// applied first, finalize second) so a single witness fixup
    /// reconstructs every eliminated wire. Routing every finalize entry
    /// through here closes the trap where collapse + an O2 finalize would
    /// otherwise silently drop the collapse map.
    fn install_finalize_substitutions(&mut self, finalize_subs: SubstitutionMap<F>) {
        let subs = match self.cs.take_collapse_substitution_map() {
            Some(collapse_subs) => {
                constraints::r1cs_optimize::compose_substitution_maps(collapse_subs, &finalize_subs)
            }
            None => finalize_subs,
        };

        if !subs.is_empty() {
            // Drop ops that produce only eliminated wires and rewrite the
            // source LCs of the survivors. The composed map is canonical,
            // so this single pass is equivalent to applying collapse then
            // finalize in sequence.
            crate::witness::apply_substitutions_to_witness_ops(&mut self.witness_ops, &subs);

            // optimize_linear replaces the constraint vec wholesale, so the
            // old per-constraint origin indices no longer map to anything;
            // clear them (the inspector degrades gracefully without origins).
            self.constraint_origins.clear();

            self.substitution_map = Some(subs);
        }
    }

    /// Run O2 constraint simplification on the compiled R1CS.
    ///
    /// Includes O1 (linear elimination) plus DEDUCE: extracts linear
    /// constraints implied by quadratic constraints via Gaussian elimination
    /// on the monomial matrix. Matches circom `--O2`.
    pub fn optimize_r1cs_o2(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_o2();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Run O2 constraint simplification with sparse-row DEDUCE.
    ///
    /// Functionally identical to `optimize_r1cs_o2` but partitions the
    /// constraint set into connected components (Union-Find on shared
    /// quadratic monomials) and runs Gaussian elimination on each
    /// component independently using `BTreeMap`-row representation.
    /// This avoids the dense `k x q` matrix that OOMs on bit-heavy
    /// circuits like SHA-256, where both dimensions exceed 60k.
    ///
    /// Clusters larger than the configured threshold are skipped --
    /// they would still fit in RAM in sparse form but full reduction
    /// without Markowitz pivoting / fill-in management is not
    /// worthwhile in this conservative path. Skipping is safe; the
    /// cluster's quadratic constraints stay in the system unchanged.
    pub fn optimize_r1cs_o2_sparse(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_o2_sparse();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Declare a public input variable and bind it to `name`.
    ///
    /// Public inputs must be declared before witnesses to maintain the
    /// snarkjs-compatible wire layout.
    pub fn declare_public(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_input();
        self.bindings.insert(name.to_string(), var);
        self.public_inputs.push(name.to_string());
        var
    }

    /// Declare a private witness variable and bind it to `name`.
    pub fn declare_witness(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_witness();
        self.bindings.insert(name.to_string(), var);
        self.witnesses.push(name.to_string());
        var
    }

    /// Materialize an LC if it exceeds the auto-materialization threshold.
    ///
    /// Prevents exponential LC term growth in long chains of Add/Sub
    /// (e.g. MDS matrix multiplication in Poseidon partial rounds).
    /// Adds at most 1 constraint per materialization.
    fn auto_materialize(&mut self, lc: LinearCombination<F>) -> LinearCombination<F> {
        if lc.terms().len() > LC_AUTO_MATERIALIZE_THRESHOLD {
            let var = self.materialize_lc(&lc);
            LinearCombination::from_variable(var)
        } else {
            lc
        }
    }

    /// Look up a previously declared variable by name.
    pub fn lookup(&self, name: &str) -> Result<Variable, R1CSError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string(), None))
    }

    /// Compile an SSA IR program into R1CS constraints.
    ///
    /// ```
    /// use zkc::r1cs_backend::R1CSCompiler;
    /// use ir::IrLowering;
    ///
    /// let prog: ir::types::IrProgram = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
    /// let mut rc = R1CSCompiler::new();
    /// rc.compile_ir(&prog).unwrap();
    /// assert!(rc.cs.num_constraints() > 0);
    /// ```
    pub fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        self.lc_map.clear();
        self.used_ssa.clear();
        self.range_bounds.clear();
        self.divmod_cache.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_ir(self, program)
    }

    /// Streaming counterpart of [`compile_ir`](Self::compile_ir): consume
    /// owned instructions from any [`IntoIterator`] source so each
    /// `Instruction<F>` drops the moment its constraints are emitted.
    /// Lets the bridge feed a Lysis interner directly into the backend
    /// without ever materializing a `Vec<Instruction<F>>`.
    ///
    /// The per-program caches are cleared up front, matching the
    /// [`compile_ir`](Self::compile_ir) contract.
    pub fn compile_instructions<I>(&mut self, instructions: I) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
        I: IntoIterator<Item = IrInstruction<F>>,
    {
        self.lc_map.clear();
        self.used_ssa.clear();
        self.range_bounds.clear();
        self.divmod_cache.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_instructions(self, instructions)
    }

    /// Multi-batch counterpart of
    /// [`compile_instructions`](Self::compile_instructions). Consumes
    /// owned instructions from any [`IntoIterator`] source like the
    /// single-batch entry point, but does **not** clear the per-program
    /// caches (`lc_map`, `range_bounds`, `divmod_cache`) on entry —
    /// state carries across calls so operands defined in an earlier
    /// batch remain resolvable in a later batch.
    ///
    /// Intended for feeding a single program in multiple batches, one
    /// batch per emission chunk from a chunk-draining lysis sink. The
    /// chunk-drain bridge minted in [`lysis::ChunkDrainingSink`] hands a
    /// `Vec<InstructionKind<F>>` to its consumer at every chunk seal;
    /// the consumer routes each chunk here so per-chunk allocations
    /// drop while operand lookup state survives the seal boundary.
    ///
    /// Caller manages cache lifecycle: invoke this on a freshly
    /// constructed [`R1CSCompiler::new`] for the first batch of a
    /// program, then continue invoking it for every subsequent batch of
    /// the same program. Reusing the compiler across distinct programs
    /// requires constructing a fresh instance — the trait's
    /// [`compile_ir`](Self::compile_ir) /
    /// [`compile_instructions`](Self::compile_instructions) entries
    /// keep the cache-clearing semantics for that case.
    ///
    /// `constraint_origins.ir_index` is the per-call iterator position
    /// (starting at 0 in every batch), not a program-global index.
    /// Consumers that depend on a program-global index must track batch
    /// starts externally.
    pub fn compile_instructions_streaming<I>(&mut self, instructions: I) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
        I: IntoIterator<Item = IrInstruction<F>>,
    {
        <Self as constraints::ConstraintBackend<F>>::compile_instructions(self, instructions)
    }
}

impl<F: FieldBackend> constraints::ConstraintBackend<F> for R1CSCompiler<F> {
    type Error = R1CSError;

    fn compile_instruction(
        &mut self,
        ir_idx: usize,
        inst: &IrInstruction<F>,
    ) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        let constraints_before = self.cs.num_constraints();

        match inst {
            IrInstruction::Const { result, value } => {
                self.cache_lc(*result, LinearCombination::from_constant(*value));
            }
            IrInstruction::Input {
                result,
                name,
                visibility,
            } => {
                let var = match visibility {
                    IrVisibility::Public => {
                        let v = self.cs.alloc_input();
                        if self.track_input_metadata {
                            self.bindings.insert(name.clone(), v);
                            self.public_inputs.push(name.clone());
                        }
                        v
                    }
                    IrVisibility::Witness => {
                        let v = self.cs.alloc_witness();
                        if self.track_input_metadata {
                            self.bindings.insert(name.clone(), v);
                            self.witnesses.push(name.clone());
                        }
                        v
                    }
                };
                self.cache_lc(*result, LinearCombination::from_variable(var));
            }
            IrInstruction::Add { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.auto_materialize(a + b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Sub { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.auto_materialize(a - b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Neg { result, operand } => {
                let lc = self.lookup_lc(operand)?;
                self.cache_lc(*result, lc * FieldElement::<F>::one().neg());
            }
            IrInstruction::Mul { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Div { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.divide_lcs(&a, &b)?;
                self.cache_lc(*result, out);
            }
            IrInstruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_lc = self.lookup_lc(cond)?;
                let then_lc = self.lookup_lc(if_true)?;
                let else_lc = self.lookup_lc(if_false)?;

                // Skip boolean enforcement if cond is proven boolean or already enforced
                if !self.proven_boolean.contains(cond) && self.bool_enforced.insert(*cond) {
                    BC_MUX_COND.fetch_add(1, Ordering::Relaxed);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    let one_minus_cond = one - cond_lc.clone();
                    self.cs
                        .enforce(cond_lc.clone(), one_minus_cond, LinearCombination::zero());
                }

                // MUX: result = cond * (then - else) + else
                let diff = then_lc - else_lc.clone();
                let selected = self.multiply_lcs(&cond_lc, &diff);
                self.cache_lc(*result, selected + else_lc);
            }
            IrInstruction::AssertEq {
                result, lhs, rhs, ..
            } => {
                let lhs_was_used = self.is_ssa_used(*lhs);
                let a = self.lookup_lc_untracked(lhs)?;
                let b = self.lookup_lc(rhs)?;
                if self.forward_assert_eq_collapse
                    && !lhs_was_used
                    && a.as_single_variable()
                        .map(|var| var.index() > self.cs.num_pub_inputs())
                        .unwrap_or(false)
                {
                    self.cache_lc(*lhs, b.clone());
                } else {
                    self.mark_ssa_used(*lhs);
                    self.cs.enforce_equal(a, b.clone());
                }
                self.cache_lc(*result, b);
            }
            IrInstruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let lc = self.lookup_lc(operand)?;
                // Boolean decomposition: x = sum(b_i * 2^i), each b_i boolean
                // Cost: bits boolean constraints + 1 sum equality = bits+1 total
                let mut sum = LinearCombination::zero();
                let two = FieldElement::<F>::from_u64(2);
                let mut coeff = FieldElement::<F>::one();
                for i in 0..*bits {
                    let bit_var = self.cs.alloc_witness();
                    // b_i * (1 - b_i) = 0  (enforces b_i ∈ {0, 1})
                    BC_RANGE_CHECK.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        LinearCombination::from_variable(bit_var),
                        LinearCombination::from_constant(FieldElement::<F>::one())
                            - LinearCombination::from_variable(bit_var),
                        LinearCombination::zero(),
                    );
                    sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                    coeff = coeff.mul(&two);
                    self.push_witness_op(WitnessOp::BitExtract {
                        target: bit_var,
                        source: lc.clone(),
                        bit_index: i,
                    });
                }
                self.cs.enforce_equal(lc.clone(), sum);
                // Record proven bound for IsLt/IsLe optimization
                self.range_bounds.insert(*operand, *bits);
                self.cache_lc(*result, lc);
            }
            IrInstruction::Not { result, operand } => {
                let op_lc = self.lookup_lc(operand)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                // Skip boolean enforcement if proven boolean or already enforced
                if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand) {
                    BC_NOT.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        op_lc.clone(),
                        one.clone() - op_lc.clone(),
                        LinearCombination::zero(),
                    );
                }
                // result = 1 - op
                self.cache_lc(*result, one - op_lc);
            }
            IrInstruction::And { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                    BC_AND_LHS.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        a.clone(),
                        one.clone() - a.clone(),
                        LinearCombination::zero(),
                    );
                }
                if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                    BC_AND_RHS.fetch_add(1, Ordering::Relaxed);
                    self.cs
                        .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                }
                // result = a * b
                let out = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Or { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                    BC_OR_LHS.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        a.clone(),
                        one.clone() - a.clone(),
                        LinearCombination::zero(),
                    );
                }
                if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                    BC_OR_RHS.fetch_add(1, Ordering::Relaxed);
                    self.cs
                        .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                }
                // result = a + b - a*b
                let product = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, a + b - product);
            }
            IrInstruction::IsEq { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let diff = a - b;
                // IsZero gadget: alloc inv + eq_result
                // enforce: diff * inv = 1 - eq_result
                // enforce: diff * eq_result = 0
                let inv_var = self.cs.alloc_witness();
                let eq_var = self.cs.alloc_witness();
                self.push_witness_op(WitnessOp::IsZero {
                    diff: diff.clone(),
                    target_inv: inv_var,
                    target_result: eq_var,
                });
                let inv_lc = LinearCombination::from_variable(inv_var);
                let eq_lc = LinearCombination::from_variable(eq_var);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cs.enforce(diff.clone(), inv_lc, one - eq_lc.clone());
                self.cs
                    .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                self.cache_lc(*result, eq_lc);
            }
            IrInstruction::IsNeq { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let diff = a - b;
                // IsZero gadget then negate
                let inv_var = self.cs.alloc_witness();
                let eq_var = self.cs.alloc_witness();
                self.push_witness_op(WitnessOp::IsZero {
                    diff: diff.clone(),
                    target_inv: inv_var,
                    target_result: eq_var,
                });
                let inv_lc = LinearCombination::from_variable(inv_var);
                let eq_lc = LinearCombination::from_variable(eq_var);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cs
                    .enforce(diff.clone(), inv_lc, one.clone() - eq_lc.clone());
                self.cs
                    .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                // neq = 1 - eq
                self.cache_lc(*result, one - eq_lc);
            }
            IrInstruction::IsLt { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let bound_a = self.range_bounds.get(lhs).copied();
                let bound_b = self.range_bounds.get(rhs).copied();
                let default_bits = self.default_range_bits();

                let effective_bits = match (bound_a, bound_b) {
                    (Some(ba), Some(bb)) => ba.max(bb),
                    _ => {
                        if bound_a.is_none() {
                            self.enforce_default_range(&a);
                        }
                        if bound_b.is_none() {
                            self.enforce_default_range(&b);
                        }
                        default_bits
                    }
                };

                let offset =
                    power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                let diff = b - a + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                self.cache_lc(*result, lt_lc);
            }
            IrInstruction::IsLe { result, lhs, rhs } => {
                // a <= b  ≡  !(b < a)  ≡  1 - IsLt(b, a)
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let bound_a = self.range_bounds.get(lhs).copied();
                let bound_b = self.range_bounds.get(rhs).copied();
                let default_bits = self.default_range_bits();

                let effective_bits = match (bound_a, bound_b) {
                    (Some(ba), Some(bb)) => ba.max(bb),
                    _ => {
                        if bound_a.is_none() {
                            self.enforce_default_range(&a);
                        }
                        if bound_b.is_none() {
                            self.enforce_default_range(&b);
                        }
                        default_bits
                    }
                };

                let offset =
                    power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                let diff = a - b + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cache_lc(*result, one - lt_lc);
            }
            IrInstruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let offset = power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                let diff = b - a + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                self.cache_lc(*result, lt_lc);
            }
            IrInstruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let offset = power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                let diff = a - b + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cache_lc(*result, one - lt_lc);
            }
            IrInstruction::Assert {
                result, operand, ..
            } => {
                let op_lc = self.lookup_lc(operand)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                // Skip boolean enforcement if proven boolean or already enforced
                if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand) {
                    BC_ASSERT.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        op_lc.clone(),
                        one.clone() - op_lc.clone(),
                        LinearCombination::zero(),
                    );
                }
                // Enforce op == 1
                self.cs.enforce_equal(op_lc.clone(), one);
                self.cache_lc(*result, op_lc);
            }
            IrInstruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let left_lc = self.lookup_lc(left)?;
                let right_lc = self.lookup_lc(right)?;

                let left_var = self.materialize_lc(&left_lc);
                let right_var = self.materialize_lc(&right_lc);

                if self.poseidon_params.is_none() {
                    self.poseidon_params = Some(F::default_poseidon_t3());
                }
                let params = self.poseidon_params.as_ref().unwrap();

                let internal_start = self.cs.num_variables();
                let hash_var = constraints::poseidon::poseidon_hash_circuit(
                    &mut self.cs,
                    params,
                    left_var,
                    right_var,
                );
                let internal_count = self.cs.num_variables() - internal_start;

                self.push_witness_op(WitnessOp::PoseidonHash {
                    left: left_var,
                    right: right_var,
                    output: hash_var,
                    internal_start,
                    internal_count,
                });

                self.cache_lc(*result, LinearCombination::from_variable(hash_var));
            }
            IrInstruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let lc = self.lookup_lc(operand)?;
                // Materialize source to avoid cloning large LC num_bits times.
                let src_var = self.materialize_lc(&lc);
                let src_lc = LinearCombination::from_variable(src_var);

                // Same as RangeCheck but also registers each bit in self.lc_map.
                let mut sum = LinearCombination::zero();
                let two = FieldElement::<F>::from_u64(2);
                let mut coeff = FieldElement::<F>::one();
                for (i, bit_ssa) in bit_results.iter().enumerate() {
                    let bit_var = self.cs.alloc_witness();
                    // b_i * (1 - b_i) = 0
                    BC_DECOMPOSE.fetch_add(1, Ordering::Relaxed);
                    if *num_bits == 1 {
                        BC_DECOMPOSE_1BIT.fetch_add(1, Ordering::Relaxed);
                    }
                    self.cs.enforce(
                        LinearCombination::from_variable(bit_var),
                        LinearCombination::from_constant(FieldElement::<F>::one())
                            - LinearCombination::from_variable(bit_var),
                        LinearCombination::zero(),
                    );
                    // Track as bool-enforced so Mux/And/Or won't emit duplicate enforcement
                    self.bool_enforced.insert(*bit_ssa);
                    sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                    coeff = coeff.mul(&two);
                    self.push_witness_op(WitnessOp::BitExtract {
                        target: bit_var,
                        source: src_lc.clone(),
                        bit_index: i as u32,
                    });
                    // Register each bit in lc_map so subsequent instructions can use it
                    self.cache_lc(*bit_ssa, LinearCombination::from_variable(bit_var));
                }
                self.cs.enforce_equal(src_lc, sum);
                self.range_bounds.insert(*operand, *num_bits);
                self.cache_lc(*result, lc);
            }
            IrInstruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let cache_key = (*lhs, *rhs, *max_bits);
                if let Some((cached_q, _)) = self.divmod_cache.get(&cache_key) {
                    // Reuse cached quotient from a previous divmod on same operands
                    self.cache_lc(*result, cached_q.clone());
                } else {
                    let a_lc = self.lookup_lc(lhs)?;
                    let b_lc = self.lookup_lc(rhs)?;

                    let q_var = self.cs.alloc_witness();
                    let r_var = self.cs.alloc_witness();

                    let lhs_var = self.materialize_lc(&a_lc);
                    let rhs_var = self.materialize_lc(&b_lc);
                    self.push_witness_op(WitnessOp::IntDivMod {
                        q: q_var,
                        r: r_var,
                        lhs: lhs_var,
                        rhs: rhs_var,
                    });

                    let q_lc = LinearCombination::from_variable(q_var);
                    let r_lc = LinearCombination::from_variable(r_var);

                    let bq = self.multiply_lcs(&b_lc, &q_lc);
                    self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

                    self.enforce_n_range(&q_lc, *max_bits);
                    self.enforce_n_range(&r_lc, *max_bits);

                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
                    self.enforce_n_range(&b_minus_r_minus_1, *max_bits);

                    self.divmod_cache.insert(cache_key, (q_lc.clone(), r_lc));
                    self.cache_lc(*result, q_lc);
                }
            }
            IrInstruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let cache_key = (*lhs, *rhs, *max_bits);
                if let Some((_, cached_r)) = self.divmod_cache.get(&cache_key) {
                    // Reuse cached remainder from a previous divmod on same operands
                    self.cache_lc(*result, cached_r.clone());
                } else {
                    let a_lc = self.lookup_lc(lhs)?;
                    let b_lc = self.lookup_lc(rhs)?;

                    let q_var = self.cs.alloc_witness();
                    let r_var = self.cs.alloc_witness();

                    let lhs_var = self.materialize_lc(&a_lc);
                    let rhs_var = self.materialize_lc(&b_lc);
                    self.push_witness_op(WitnessOp::IntDivMod {
                        q: q_var,
                        r: r_var,
                        lhs: lhs_var,
                        rhs: rhs_var,
                    });

                    let q_lc = LinearCombination::from_variable(q_var);
                    let r_lc = LinearCombination::from_variable(r_var);

                    let bq = self.multiply_lcs(&b_lc, &q_lc);
                    self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

                    self.enforce_n_range(&q_lc, *max_bits);
                    self.enforce_n_range(&r_lc, *max_bits);

                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
                    self.enforce_n_range(&b_minus_r_minus_1, *max_bits);

                    self.divmod_cache.insert(cache_key, (q_lc, r_lc.clone()));
                    self.cache_lc(*result, r_lc);
                }
            }
            IrInstruction::WitnessCall(call) => {
                // Each output is a fresh witness wire — no
                // constraints are emitted here. The prover's
                // witness generator replays the Artik program
                // against `inputs` at witness-gen time to fill
                // the wires.
                let mut input_vars: Vec<Variable> = Vec::with_capacity(call.inputs.len());
                for v in &call.inputs {
                    let lc = self.lookup_lc(v)?;
                    input_vars.push(self.materialize_lc(&lc));
                }
                let mut output_vars: Vec<Variable> = Vec::with_capacity(call.outputs.len());
                for out_ssa in &call.outputs {
                    let out_var = self.cs.alloc_witness();
                    output_vars.push(out_var);
                    self.cache_lc(*out_ssa, LinearCombination::from_variable(out_var));
                }
                let interned = self.intern_artik_program(&call.program_bytes);
                self.push_witness_op(WitnessOp::ArtikCall {
                    outputs: output_vars,
                    inputs: input_vars,
                    program_bytes: interned,
                });
            }
        }

        // Record which IR instruction generated each new constraint, when
        // the compiler was constructed in tracking mode.
        if self.track_constraint_origins {
            let constraints_after = self.cs.num_constraints();
            let result_var = inst.result_var();
            for _ in constraints_before..constraints_after {
                self.constraint_origins.push(ConstraintOrigin {
                    ir_index: ir_idx,
                    result_var,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::types::{Instruction, IrProgram, SsaVar, Visibility as IrVisibility};

    #[test]
    fn constraint_origins_tracks_mul() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        // Mul generates exactly 1 constraint
        assert_eq!(compiler.cs.num_constraints(), 1);
        assert_eq!(compiler.constraint_origins.len(), 1);
        assert_eq!(compiler.constraint_origins[0].ir_index, 2); // third instruction
        assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
    }

    #[test]
    fn constraint_origins_tracks_assert_eq() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Public,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v2,
            lhs: v0,
            rhs: v1,
            message: Some("values must match".into()),
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(compiler.cs.num_constraints(), 1);
        assert_eq!(compiler.constraint_origins.len(), 1);
        assert_eq!(compiler.constraint_origins[0].ir_index, 2);
        assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
    }

    #[test]
    fn constraint_origins_empty_for_linear_ops() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        // Add is free (no constraints)
        let v2 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(compiler.cs.num_constraints(), 0);
        assert!(compiler.constraint_origins.is_empty());
    }

    #[test]
    fn constraint_origins_count_matches_constraints() {
        // Mixed circuit: Mul + PoseidonHash + AssertEq
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v3,
            left: v0,
            right: v1,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v4,
            lhs: v2,
            rhs: v3,
            message: None,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        // Origins length must match constraint count exactly
        assert_eq!(
            compiler.constraint_origins.len(),
            compiler.cs.num_constraints()
        );

        // Verify Poseidon constraints map back to the PoseidonHash instruction (index 3)
        let poseidon_origins: Vec<_> = compiler
            .constraint_origins
            .iter()
            .filter(|o| o.ir_index == 3)
            .collect();
        assert_eq!(poseidon_origins.len(), 361); // PoseidonHash = 361 constraints
    }

    #[test]
    fn compile_instructions_matches_compile_ir_on_mixed_circuit() {
        // Pin: the streaming `compile_instructions` entry point and
        // the eager `compile_ir(&IrProgram)` entry point produce
        // byte-identical R1CS output (same constraint count, same
        // constraint_origins) on a representative mixed circuit.
        // Reuses the constraint_origins_count_matches_constraints
        // shape.
        let build_prog = || {
            let mut prog: IrProgram = IrProgram::new();
            let v0 = prog.fresh_var();
            prog.push(Instruction::Input {
                result: v0,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            });
            let v1 = prog.fresh_var();
            prog.push(Instruction::Input {
                result: v1,
                name: "y".into(),
                visibility: IrVisibility::Witness,
            });
            let v2 = prog.fresh_var();
            prog.push(Instruction::Mul {
                result: v2,
                lhs: v0,
                rhs: v1,
            });
            let v3 = prog.fresh_var();
            prog.push(Instruction::PoseidonHash {
                result: v3,
                left: v0,
                right: v1,
            });
            let v4 = prog.fresh_var();
            prog.push(Instruction::AssertEq {
                result: v4,
                lhs: v0,
                rhs: v1,
                message: None,
            });
            prog
        };

        let mut eager = R1CSCompiler::new();
        eager.compile_ir(&build_prog()).unwrap();

        let mut streaming = R1CSCompiler::new();
        streaming
            .compile_instructions(build_prog().into_instructions())
            .unwrap();

        assert_eq!(eager.cs.num_constraints(), streaming.cs.num_constraints());
        assert_eq!(
            eager.constraint_origins.len(),
            streaming.constraint_origins.len()
        );
        for (a, b) in eager
            .constraint_origins
            .iter()
            .zip(streaming.constraint_origins.iter())
        {
            assert_eq!(a.ir_index, b.ir_index);
            assert_eq!(a.result_var, b.result_var);
        }
    }

    #[test]
    fn lean_compiler_skips_constraint_origins() {
        // Pin: a compiler built via `new_lean` leaves `constraint_origins`
        // empty after emission, while the eager `new` constructor populates
        // it as usual on the same program.
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let mut lean = R1CSCompiler::new_lean();
        lean.compile_ir(&prog).unwrap();
        assert!(
            lean.constraint_origins.is_empty(),
            "lean compiler must not populate constraint_origins"
        );
        assert!(
            lean.cs.num_constraints() > 0,
            "lean compiler must still emit constraints"
        );
    }

    #[test]
    fn lean_compiler_skips_input_metadata_but_preserves_wire_layout() {
        // Pin: `new_lean` is allowed to drop name metadata, but it must still
        // allocate public and witness wires exactly like the eager compiler.
        let mut prog: IrProgram = IrProgram::new();
        let pub_var = prog.fresh_var();
        prog.push(Instruction::Input {
            result: pub_var,
            name: "public_out".into(),
            visibility: IrVisibility::Public,
        });
        let witness_var = prog.fresh_var();
        prog.push(Instruction::Input {
            result: witness_var,
            name: "__lysis_sym_slot_42".into(),
            visibility: IrVisibility::Witness,
        });
        let assertion = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: assertion,
            lhs: pub_var,
            rhs: witness_var,
            message: None,
        });

        let mut eager = R1CSCompiler::new();
        eager.compile_ir(&prog).unwrap();

        let mut lean = R1CSCompiler::new_lean();
        lean.compile_ir(&prog).unwrap();

        assert_eq!(eager.cs.num_variables(), lean.cs.num_variables());
        assert_eq!(eager.cs.num_pub_inputs(), lean.cs.num_pub_inputs());
        assert_eq!(eager.cs.num_constraints(), lean.cs.num_constraints());
        assert_eq!(eager.bindings.len(), 2);
        assert_eq!(eager.public_inputs, vec!["public_out"]);
        assert_eq!(eager.witnesses, vec!["__lysis_sym_slot_42"]);
        assert!(lean.bindings.is_empty());
        assert!(lean.public_inputs.is_empty());
        assert!(lean.witnesses.is_empty());
    }

    #[test]
    fn lean_compiler_matches_eager_on_constraint_surface() {
        // Pin: lean and eager R1CS compilers produce byte-identical
        // constraint systems on a representative mixed circuit — same
        // count, same per-constraint LC terms, same witness ops, same
        // variable allocations. Lean deliberately drops hot-path metadata:
        // constraint origins and input name tables.
        let build_prog = || {
            let mut prog: IrProgram = IrProgram::new();
            let v0 = prog.fresh_var();
            prog.push(Instruction::Input {
                result: v0,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            });
            let v1 = prog.fresh_var();
            prog.push(Instruction::Input {
                result: v1,
                name: "y".into(),
                visibility: IrVisibility::Witness,
            });
            let v2 = prog.fresh_var();
            prog.push(Instruction::Mul {
                result: v2,
                lhs: v0,
                rhs: v1,
            });
            let v3 = prog.fresh_var();
            prog.push(Instruction::PoseidonHash {
                result: v3,
                left: v0,
                right: v1,
            });
            let v4 = prog.fresh_var();
            prog.push(Instruction::AssertEq {
                result: v4,
                lhs: v0,
                rhs: v1,
                message: None,
            });
            prog
        };

        let mut eager = R1CSCompiler::new();
        eager.compile_ir(&build_prog()).unwrap();

        let mut lean = R1CSCompiler::new_lean();
        lean.compile_ir(&build_prog()).unwrap();

        assert_eq!(eager.cs.num_constraints(), lean.cs.num_constraints());
        assert_eq!(eager.cs.num_variables(), lean.cs.num_variables());
        assert_eq!(eager.cs.num_pub_inputs(), lean.cs.num_pub_inputs());
        assert_eq!(eager.witness_ops.len(), lean.witness_ops.len());

        for (e, l) in eager
            .cs
            .constraints()
            .iter()
            .zip(lean.cs.constraints().iter())
        {
            assert_eq!(e.a.terms(), l.a.terms(), "constraint.a terms diverged");
            assert_eq!(e.b.terms(), l.b.terms(), "constraint.b terms diverged");
            assert_eq!(e.c.terms(), l.c.terms(), "constraint.c terms diverged");
        }

        assert!(
            !eager.constraint_origins.is_empty(),
            "eager compiler must populate origins"
        );
        assert!(
            lean.constraint_origins.is_empty(),
            "lean compiler must leave origins empty"
        );
        assert!(
            lean.bindings.is_empty() && lean.public_inputs.is_empty() && lean.witnesses.is_empty(),
            "lean compiler must leave input metadata empty"
        );
    }

    #[test]
    fn assert_eq_rebinds_fresh_private_lhs_without_linear_constraint() {
        let mut prog: IrProgram = IrProgram::new();
        let x = prog.fresh_var();
        prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let y = prog.fresh_var();
        prog.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let eq = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: eq,
            lhs: x,
            rhs: y,
            message: None,
        });
        let product = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: product,
            lhs: x,
            rhs: y,
        });

        let mut compiler = R1CSCompiler::<Bn254Fr>::new_lean();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(
            compiler.cs.num_constraints(),
            1,
            "fresh private AssertEq lhs should become a forward alias, not a stored linear constraint"
        );
        let constraint = &compiler.cs.constraints()[0];
        assert_eq!(constraint.a.terms(), &[(Variable(2), FieldElement::ONE)]);
        assert_eq!(constraint.b.terms(), &[(Variable(2), FieldElement::ONE)]);
    }

    #[test]
    fn assert_eq_keeps_constraint_for_used_or_public_lhs() {
        let mut used_prog: IrProgram = IrProgram::new();
        let x = used_prog.fresh_var();
        used_prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let y = used_prog.fresh_var();
        used_prog.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let first_product = used_prog.fresh_var();
        used_prog.push(Instruction::Mul {
            result: first_product,
            lhs: x,
            rhs: y,
        });
        let eq = used_prog.fresh_var();
        used_prog.push(Instruction::AssertEq {
            result: eq,
            lhs: x,
            rhs: y,
            message: None,
        });

        let mut used_compiler = R1CSCompiler::<Bn254Fr>::new_lean();
        used_compiler.compile_ir(&used_prog).unwrap();
        assert_eq!(
            used_compiler.cs.num_constraints(),
            2,
            "lhs already used by a prior expression must keep its equality constraint"
        );

        let mut public_prog: IrProgram = IrProgram::new();
        let out = public_prog.fresh_var();
        public_prog.push(Instruction::Input {
            result: out,
            name: "out".into(),
            visibility: IrVisibility::Public,
        });
        let y = public_prog.fresh_var();
        public_prog.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let eq = public_prog.fresh_var();
        public_prog.push(Instruction::AssertEq {
            result: eq,
            lhs: out,
            rhs: y,
            message: None,
        });

        let mut public_compiler = R1CSCompiler::<Bn254Fr>::new_lean();
        public_compiler.compile_ir(&public_prog).unwrap();
        assert_eq!(
            public_compiler.cs.num_constraints(),
            1,
            "public lhs must stay constrained to preserve the public interface"
        );
    }

    #[test]
    fn compile_instructions_streaming_resolves_operands_across_batches() {
        // Pin: `compile_instructions_streaming` does NOT clear the
        // per-program operand-lookup caches between calls, so an
        // operand defined in an earlier batch remains resolvable in a
        // later batch. The chunk-draining lysis-to-R1CS bridge relies
        // on this: a `Mul` (or any operand-taking instruction) sealed
        // into chunk N may reference an SsaVar first emitted in chunk
        // M<N when the interner's dedup tiers return a cross-chunk
        // `NodeId`. Wipe the cache per chunk and the cross-chunk
        // operand lookup fails.
        //
        // The companion `compile_instructions_does_clear_caches_*` test
        // below shows the dual: feeding the same batched stream through
        // the single-batch `compile_instructions` entry point fails on
        // the second batch because its operands look up wires the
        // entry point cleared.
        let build_prog = || {
            let mut prog: IrProgram = IrProgram::new();
            let x = prog.fresh_var();
            prog.push(Instruction::Input {
                result: x,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            });
            let c = prog.fresh_var();
            prog.push(Instruction::Const {
                result: c,
                value: FieldElement::<Bn254Fr>::from_u64(5),
            });
            let y = prog.fresh_var();
            prog.push(Instruction::Mul {
                result: y,
                lhs: x,
                rhs: c,
            });
            let out = prog.fresh_var();
            prog.push(Instruction::Input {
                result: out,
                name: "out".into(),
                visibility: IrVisibility::Public,
            });
            let assertion = prog.fresh_var();
            prog.push(Instruction::AssertEq {
                result: assertion,
                lhs: y,
                rhs: out,
                message: None,
            });
            prog
        };

        // Reference path: single eager `compile_ir` call.
        let mut eager = R1CSCompiler::<Bn254Fr>::new();
        eager.compile_ir(&build_prog()).unwrap();

        // Subject path: split the same program across three batches.
        // Batch 1 defines `x` (Input) and `c` (Const).
        // Batch 2 has `Mul y = x * c` — operands cross the batch
        //   boundary; both `x` and `c` were defined in batch 1.
        // Batch 3 defines `out` (Input) and asserts `y == out` —
        //   the AssertEq references `y` from batch 2 and `out` from
        //   batch 3, exercising both cross-batch and within-batch
        //   operand lookup on the same call.
        let instrs: Vec<_> = build_prog().into_instructions();
        let batch1: Vec<_> = instrs[0..2].to_vec();
        let batch2: Vec<_> = instrs[2..3].to_vec();
        let batch3: Vec<_> = instrs[3..].to_vec();

        let mut streaming = R1CSCompiler::<Bn254Fr>::new();
        streaming.compile_instructions_streaming(batch1).unwrap();
        streaming.compile_instructions_streaming(batch2).unwrap();
        streaming.compile_instructions_streaming(batch3).unwrap();

        assert_eq!(eager.cs.num_constraints(), streaming.cs.num_constraints());
        assert_eq!(eager.cs.num_variables(), streaming.cs.num_variables());
        assert_eq!(eager.cs.num_pub_inputs(), streaming.cs.num_pub_inputs());
        assert_eq!(eager.public_inputs, streaming.public_inputs);
        assert_eq!(eager.witnesses, streaming.witnesses);
    }

    #[test]
    fn compile_instructions_clears_caches_so_batched_operand_lookup_fails() {
        // Dual of the streaming pin: feeding the SAME batched stream
        // through the single-batch `compile_instructions` entry point
        // fails on the second batch because the entry point clears
        // `lc_map` on every call. Pinning this guards against an
        // accidental removal of the clearing semantics from
        // `compile_instructions` proper — that entry point IS the
        // "fresh compiler per program" boundary; the streaming entry
        // point is the explicit opt-in to no-clear behavior.
        let mut prog: IrProgram = IrProgram::new();
        let x = prog.fresh_var();
        prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let c = prog.fresh_var();
        prog.push(Instruction::Const {
            result: c,
            value: FieldElement::<Bn254Fr>::from_u64(5),
        });
        let y = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: y,
            lhs: x,
            rhs: c,
        });
        let instrs: Vec<_> = prog.into_instructions();
        let batch1: Vec<_> = instrs[0..2].to_vec();
        let batch2: Vec<_> = instrs[2..].to_vec();

        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler.compile_instructions(batch1).unwrap();
        // Batch 2 references `x` and `c` from batch 1; the entry
        // point cleared `lc_map` on entry, so lookup fails.
        let err = compiler.compile_instructions(batch2).unwrap_err();
        assert!(
            matches!(err, R1CSError::UnsupportedOperation(_, _)),
            "expected undefined-SSA-variable error, got {err:?}"
        );
    }

    /// Build an `IrProgram` that emits two `WitnessCall`s. Each call
    /// declares one fresh input and one fresh output; `program_bytes`
    /// per call is supplied by the caller. The bytecode is opaque to
    /// `compile_ir` — it is only stored, never decoded.
    fn build_two_witness_call_prog(bytes_a: Vec<u8>, bytes_b: Vec<u8>) -> IrProgram {
        use ir::types::WitnessCallBody;

        let mut prog: IrProgram = IrProgram::new();
        let in_a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: in_a,
            name: "in_a".into(),
            visibility: IrVisibility::Witness,
        });
        let in_b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: in_b,
            name: "in_b".into(),
            visibility: IrVisibility::Witness,
        });
        let out_a = prog.fresh_var();
        prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![out_a],
            inputs: vec![in_a],
            program_bytes: bytes_a,
        })));
        let out_b = prog.fresh_var();
        prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![out_b],
            inputs: vec![in_b],
            program_bytes: bytes_b,
        })));
        prog
    }

    #[test]
    fn artik_intern_shares_arc_for_identical_payloads() {
        // Pin: two `WitnessCall`s carrying byte-identical `program_bytes`
        // collapse to a single `Arc<[u8]>` in the intern table, and the
        // resulting `WitnessOp::ArtikCall` entries share the same pointer.
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let prog = build_two_witness_call_prog(payload.clone(), payload.clone());

        let mut c = R1CSCompiler::<Bn254Fr>::new();
        c.compile_ir(&prog).unwrap();

        assert_eq!(
            c.artik_program_intern_len(),
            1,
            "byte-identical payloads must collapse to a single intern entry"
        );

        let artik_ops: Vec<&WitnessOp<_>> = c
            .witness_ops
            .iter()
            .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
            .collect();
        assert_eq!(artik_ops.len(), 2, "expected two ArtikCall entries");
        let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
            (
                WitnessOp::ArtikCall {
                    program_bytes: pa, ..
                },
                WitnessOp::ArtikCall {
                    program_bytes: pb, ..
                },
            ) => (pa, pb),
            _ => unreachable!(),
        };
        assert!(
            Arc::ptr_eq(a, b),
            "intern table must hand out the same Arc to identical payloads"
        );
    }

    #[test]
    fn artik_intern_survives_across_streaming_batches() {
        // Pin: the intern table is owned by the compiler, not by a
        // single `compile_ir` call, so two `compile_instructions_streaming`
        // batches that each carry a byte-identical `WitnessCall` payload
        // still collapse to a single `Arc<[u8]>`. The chunk-drain entry
        // point relies on this — it routes each sealed chunk through
        // `compile_instructions_streaming` against the same compiler,
        // so intern hits must accumulate across chunks.
        use ir::types::WitnessCallBody;

        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let mut prog: IrProgram = IrProgram::new();
        let in_a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: in_a,
            name: "in_a".into(),
            visibility: IrVisibility::Witness,
        });
        let out_a = prog.fresh_var();
        prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![out_a],
            inputs: vec![in_a],
            program_bytes: payload.clone(),
        })));
        let in_b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: in_b,
            name: "in_b".into(),
            visibility: IrVisibility::Witness,
        });
        let out_b = prog.fresh_var();
        prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![out_b],
            inputs: vec![in_b],
            program_bytes: payload.clone(),
        })));

        let instrs: Vec<_> = prog.into_instructions();
        let batch1: Vec<_> = instrs[0..2].to_vec();
        let batch2: Vec<_> = instrs[2..].to_vec();

        let mut c = R1CSCompiler::<Bn254Fr>::new();
        c.compile_instructions_streaming(batch1).unwrap();
        c.compile_instructions_streaming(batch2).unwrap();

        assert_eq!(
            c.artik_program_intern_len(),
            1,
            "intern table must persist across streaming batches"
        );
        let artik_ops: Vec<&WitnessOp<_>> = c
            .witness_ops
            .iter()
            .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
            .collect();
        assert_eq!(artik_ops.len(), 2);
        let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
            (
                WitnessOp::ArtikCall {
                    program_bytes: pa, ..
                },
                WitnessOp::ArtikCall {
                    program_bytes: pb, ..
                },
            ) => (pa, pb),
            _ => unreachable!(),
        };
        assert!(
            Arc::ptr_eq(a, b),
            "Arc identity must hold across streaming batch boundaries"
        );
    }

    #[test]
    fn artik_intern_keeps_distinct_arcs_for_different_payloads() {
        // Pin: payloads that differ in even a single byte get distinct
        // intern entries and distinct `Arc`s — the secondary slice
        // equality check guards against any `u64` hash collision aliasing
        // the two programs.
        let prog = build_two_witness_call_prog(vec![0xAA, 0xBB], vec![0xAA, 0xCC]);

        let mut c = R1CSCompiler::<Bn254Fr>::new();
        c.compile_ir(&prog).unwrap();

        assert_eq!(
            c.artik_program_intern_len(),
            2,
            "byte-distinct payloads must occupy distinct intern entries"
        );

        let artik_ops: Vec<&WitnessOp<_>> = c
            .witness_ops
            .iter()
            .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
            .collect();
        let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
            (
                WitnessOp::ArtikCall {
                    program_bytes: pa, ..
                },
                WitnessOp::ArtikCall {
                    program_bytes: pb, ..
                },
            ) => (pa, pb),
            _ => unreachable!(),
        };
        assert!(
            !Arc::ptr_eq(a, b),
            "distinct payloads must NOT share an Arc"
        );
        assert_eq!(a.as_ref(), &[0xAA, 0xBB][..]);
        assert_eq!(b.as_ref(), &[0xAA, 0xCC][..]);
    }

    #[test]
    fn direct_linear_mul_emits_post_o1_shape_for_multi_term_operands() {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: IrVisibility::Witness,
        });
        let b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: IrVisibility::Witness,
        });
        let c = prog.fresh_var();
        prog.push(Instruction::Input {
            result: c,
            name: "c".into(),
            visibility: IrVisibility::Witness,
        });
        let ab = prog.fresh_var();
        prog.push(Instruction::Add {
            result: ab,
            lhs: a,
            rhs: b,
        });
        let bc = prog.fresh_var();
        prog.push(Instruction::Add {
            result: bc,
            lhs: b,
            rhs: c,
        });
        let product = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: product,
            lhs: ab,
            rhs: bc,
        });

        let mut baseline = R1CSCompiler::<Bn254Fr>::new_lean();
        baseline.compile_ir(&prog).unwrap();
        assert_eq!(
            baseline.cs.num_constraints(),
            3,
            "baseline emits two materialization constraints plus the product"
        );

        let mut direct = R1CSCompiler::<Bn254Fr>::new_direct_linear_mul();
        direct.compile_ir(&prog).unwrap();
        assert_eq!(
            direct.cs.num_constraints(),
            1,
            "direct mode emits the product constraint without O1-only materializations"
        );
        assert_eq!(
            direct.witness_ops.len(),
            1,
            "direct mode records only the product witness op"
        );
        assert!(matches!(
            direct.witness_ops.iter().next(),
            Some(WitnessOp::Multiply { a, b, .. }) if a.terms().len() == 2 && b.terms().len() == 2
        ));
    }

    #[test]
    fn compile_only_direct_linear_mul_counts_constraints_without_retaining_rows() {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: IrVisibility::Witness,
        });
        let b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: IrVisibility::Witness,
        });
        let sum = prog.fresh_var();
        prog.push(Instruction::Add {
            result: sum,
            lhs: a,
            rhs: b,
        });
        let product = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: product,
            lhs: sum,
            rhs: a,
        });

        let mut direct = R1CSCompiler::<Bn254Fr>::new_direct_linear_mul();
        direct.compile_ir(&prog).unwrap();

        let mut compile_only = R1CSCompiler::<Bn254Fr>::new_compile_only_direct_linear_mul();
        compile_only.compile_ir(&prog).unwrap();

        assert_eq!(
            compile_only.cs.num_constraints(),
            direct.cs.num_constraints()
        );
        assert_eq!(compile_only.cs.num_variables(), direct.cs.num_variables());
        assert!(compile_only.cs.constraints().is_empty());
        assert!(!compile_only.cs.constraint_retention_enabled());
        assert!(
            compile_only.witness_ops.is_empty(),
            "compile-only mode must not retain witness replay ops"
        );
    }

    #[test]
    fn lc_cache_term_limit_materializes_long_cached_lcs() {
        let build_prog = || {
            let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
            let x = prog.fresh_var();
            prog.push(Instruction::Input {
                result: x,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            });
            let y = prog.fresh_var();
            prog.push(Instruction::Input {
                result: y,
                name: "y".into(),
                visibility: IrVisibility::Witness,
            });
            let z = prog.fresh_var();
            prog.push(Instruction::Input {
                result: z,
                name: "z".into(),
                visibility: IrVisibility::Witness,
            });
            let xy = prog.fresh_var();
            prog.push(Instruction::Add {
                result: xy,
                lhs: x,
                rhs: y,
            });
            let xyz = prog.fresh_var();
            prog.push(Instruction::Add {
                result: xyz,
                lhs: xy,
                rhs: z,
            });
            (prog, xyz)
        };

        let (prog, xyz) = build_prog();
        let mut unbounded = R1CSCompiler::new_lean();
        unbounded.compile_ir(&prog).unwrap();
        assert_eq!(unbounded.cs.num_constraints(), 0);
        assert_eq!(
            unbounded.lookup_lc_untracked(&xyz).unwrap().terms().len(),
            3
        );

        let (prog, xyz) = build_prog();
        let mut bounded = R1CSCompiler::new_lean();
        bounded.lc_cache_term_limit = Some(1);
        bounded.compile_ir(&prog).unwrap();
        assert_eq!(
            bounded.lookup_lc_untracked(&xyz).unwrap().terms().len(),
            1,
            "bounded cache should retain only the materialized wire"
        );
        assert_eq!(
            bounded.cs.num_constraints(),
            2,
            "x+y and (x+y)+z each cross the one-term cache limit"
        );
    }

    #[test]
    fn lc_cache_term_limit_with_collapse_absorbs_materialization_rows() {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: IrVisibility::Witness,
        });
        let b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: IrVisibility::Witness,
        });
        let c = prog.fresh_var();
        prog.push(Instruction::Input {
            result: c,
            name: "c".into(),
            visibility: IrVisibility::Witness,
        });
        let ab = prog.fresh_var();
        prog.push(Instruction::Add {
            result: ab,
            lhs: a,
            rhs: b,
        });
        let bc = prog.fresh_var();
        prog.push(Instruction::Add {
            result: bc,
            lhs: b,
            rhs: c,
        });
        let product = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: product,
            lhs: ab,
            rhs: bc,
        });

        let mut bounded = R1CSCompiler::new_direct_linear_mul();
        bounded.lc_cache_term_limit = Some(1);
        bounded.compile_ir(&prog).unwrap();
        assert_eq!(
            bounded.cs.num_constraints(),
            3,
            "without collapse, two cache materializations inflate the direct product"
        );

        let mut collapsed = R1CSCompiler::new_direct_linear_mul();
        collapsed.lc_cache_term_limit = Some(1);
        collapsed.cs.enable_incremental_collapse();
        collapsed.compile_ir(&prog).unwrap();
        assert_eq!(
            collapsed.cs.num_constraints(),
            1,
            "collapse should absorb cache materialization rows before the product survivor"
        );
        assert_eq!(
            collapsed.lookup_lc_untracked(&ab).unwrap().terms().len(),
            1,
            "bounded cache still retains only the materialized wire"
        );
    }

    #[test]
    fn count_only_collapse_absorbs_cache_rows_without_substitution_retention() {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: IrVisibility::Witness,
        });
        let b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: IrVisibility::Witness,
        });
        let c = prog.fresh_var();
        prog.push(Instruction::Input {
            result: c,
            name: "c".into(),
            visibility: IrVisibility::Witness,
        });
        let ab = prog.fresh_var();
        prog.push(Instruction::Add {
            result: ab,
            lhs: a,
            rhs: b,
        });
        let bc = prog.fresh_var();
        prog.push(Instruction::Add {
            result: bc,
            lhs: b,
            rhs: c,
        });
        let product = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: product,
            lhs: ab,
            rhs: bc,
        });

        let mut compiler = R1CSCompiler::new_direct_linear_mul();
        compiler.record_witness_ops = false;
        compiler.lc_cache_term_limit = Some(1);
        compiler.cs.disable_constraint_retention();
        compiler.cs.enable_incremental_collapse_count_only();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(
            compiler.cs.num_constraints(),
            1,
            "count-only collapse should absorb cache materialization rows"
        );
        assert!(compiler.cs.constraints().is_empty());
        assert!(
            compiler
                .cs
                .take_collapse_substitution_map()
                .unwrap()
                .is_empty(),
            "compile-only count mode must not retain eliminated-wire replacements"
        );
    }

    #[test]
    fn lc_map_get_returns_none_for_unknown_var() {
        let map: LcMap<Bn254Fr> = LcMap::new();
        assert!(map.get(&SsaVar(0)).is_none());
        assert!(map.get(&SsaVar(42)).is_none());
    }

    #[test]
    fn lc_map_keep_last_hides_old_entries_and_drops_segments() {
        let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
        map.set_keep_last_vars(Some(5));

        for i in 0..10 {
            map.insert(
                SsaVar(i),
                LinearCombination::from_variable(Variable(i as usize + 1)),
            );
        }

        assert!(
            map.get(&SsaVar(4)).is_none(),
            "entries outside the configured sliding window must not be readable"
        );
        assert!(map.get(&SsaVar(5)).is_some());
        assert!(map.get(&SsaVar(9)).is_some());
        assert_eq!(
            map.allocated_segment_count(),
            2,
            "segments wholly below the sliding window should be released"
        );
    }

    #[test]
    fn lc_map_keep_prefix_survives_sliding_window() {
        let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
        map.set_keep_prefix_vars(2);
        map.set_keep_last_vars(Some(3));

        for i in 0..12 {
            map.insert(
                SsaVar(i),
                LinearCombination::from_variable(Variable(i as usize + 1)),
            );
        }

        assert!(map.get(&SsaVar(0)).is_some());
        assert!(map.get(&SsaVar(1)).is_some());
        assert!(
            map.get(&SsaVar(4)).is_none(),
            "non-prefix entries outside the sliding window should be hidden"
        );
        assert!(map.get(&SsaVar(9)).is_some());
        assert_eq!(
            map.allocated_segment_count(),
            2,
            "prefix segment plus current sliding segment should remain"
        );
    }

    #[test]
    fn lc_map_keep_last_reports_undefined_for_evicted_operand() {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let x = prog.fresh_var();
        prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        for i in 0..4 {
            let v = prog.fresh_var();
            prog.push(Instruction::Const {
                result: v,
                value: FieldElement::<Bn254Fr>::from_u64(i),
            });
        }
        let y = prog.fresh_var();
        prog.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let out = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: out,
            lhs: x,
            rhs: y,
        });

        let mut compiler = R1CSCompiler::new_direct_linear_mul();
        compiler.lc_map.set_keep_last_vars(Some(3));
        let err = compiler.compile_ir(&prog).unwrap_err();
        assert!(
            matches!(err, R1CSError::UnsupportedOperation(_, _)),
            "a too-small sliding LC map should fail loudly on old operand reuse"
        );
    }

    #[test]
    fn used_ssa_keep_last_hides_old_marks_and_drops_segments() {
        let mut used = UsedSsaSet::with_segment_bits(64);
        used.set_keep_last_vars(Some(64));

        used.mark(SsaVar(1));
        used.mark(SsaVar(130));

        assert!(!used.contains(SsaVar(1)));
        assert!(used.contains(SsaVar(130)));
        assert_eq!(used.word_count(), 1);
    }

    #[test]
    fn used_ssa_keep_prefix_survives_sliding_window() {
        let mut used = UsedSsaSet::with_segment_bits(64);
        used.set_keep_prefix_vars(64);
        used.set_keep_last_vars(Some(64));

        used.mark(SsaVar(1));
        used.mark(SsaVar(130));

        assert!(used.contains(SsaVar(1)));
        assert!(used.contains(SsaVar(130)));
        assert_eq!(used.word_count(), 2);
    }

    #[test]
    fn lc_map_insert_at_contiguous_indices_round_trips() {
        let mut map: LcMap<Bn254Fr> = LcMap::new();
        for i in 0..16u64 {
            let mut lc = LinearCombination::<Bn254Fr>::zero();
            lc.add_term(Variable(i as usize + 1), FieldElement::<Bn254Fr>::one());
            map.insert(SsaVar(i), lc);
        }
        for i in 0..16u64 {
            let got = map.get(&SsaVar(i)).expect("var was just inserted");
            assert_eq!(got.terms().len(), 1);
            assert_eq!(got.terms()[0].0, Variable(i as usize + 1));
        }
    }

    #[test]
    fn lc_map_clear_drops_all_entries_and_keeps_get_safe() {
        let mut map: LcMap<Bn254Fr> = LcMap::new();
        map.insert(SsaVar(0), LinearCombination::<Bn254Fr>::zero());
        map.insert(SsaVar(1), LinearCombination::<Bn254Fr>::zero());
        map.clear();
        assert!(map.get(&SsaVar(0)).is_none());
        assert!(map.get(&SsaVar(1)).is_none());
        // After clear, density-1.0 invariant restarts from idx 0.
        map.insert(SsaVar(0), LinearCombination::<Bn254Fr>::zero());
        assert!(map.get(&SsaVar(0)).is_some());
    }

    #[test]
    fn lc_map_insert_overwrites_existing_idx() {
        let mut map: LcMap<Bn254Fr> = LcMap::new();
        let mut first = LinearCombination::<Bn254Fr>::zero();
        first.add_term(Variable(7), FieldElement::<Bn254Fr>::one());
        map.insert(SsaVar(0), first);
        let mut second = LinearCombination::<Bn254Fr>::zero();
        second.add_term(Variable(99), FieldElement::<Bn254Fr>::one());
        map.insert(SsaVar(0), second);
        let got = map.get(&SsaVar(0)).expect("just overwrote");
        assert_eq!(got.terms()[0].0, Variable(99));
    }

    #[test]
    fn lc_map_insert_at_high_idx_fills_intermediate_with_none() {
        // Sparse insertion is permitted (the compile_ir path may hit
        // small holes when an upstream DCE pass drops instructions
        // without renumbering SSA ids). The segmented layout bounds
        // individual allocation size while preserving direct indexing.
        let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
        map.insert(SsaVar(5), LinearCombination::<Bn254Fr>::zero());
        assert!(map.get(&SsaVar(5)).is_some());
        for i in 0..5u64 {
            assert!(map.get(&SsaVar(i)).is_none());
        }
        assert_eq!(map.allocated_segment_count(), 1);
        assert_eq!(map.slot_count(), 4);
    }

    #[test]
    fn lc_map_dense_growth_allocates_bounded_segments() {
        let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
        for i in 0..9u64 {
            map.insert(SsaVar(i), LinearCombination::<Bn254Fr>::zero());
        }
        assert_eq!(map.allocated_segment_count(), 3);
        assert_eq!(map.slot_count(), 12);
        for i in 0..9u64 {
            assert!(map.get(&SsaVar(i)).is_some());
        }
    }

    #[test]
    fn streaming_path_emits_contiguous_ssavar_ids_pin() {
        // Density-1.0 codification on the streaming path used by the
        // chunk-drain boss-fight wiring. Feed a small IR program
        // through `compile_instructions_streaming` and check every
        // result SsaVar landed in lc_map at the expected contiguous
        // index — same insert path that the chunk-drain consumer
        // exercises at million-instruction scale.
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v3,
            lhs: v2,
            rhs: v0,
        });

        let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
        compiler
            .compile_instructions_streaming(prog.iter().cloned())
            .unwrap();
        for i in 0..=3u64 {
            assert!(
                compiler.lc_map.get(&SsaVar(i)).is_some(),
                "SsaVar({i}) must be populated"
            );
        }
        assert_eq!(
            compiler.lc_map.slot_count(),
            LcMap::<Bn254Fr>::DEFAULT_SEGMENT_LEN
        );
    }

    #[test]
    fn lc_map_insert_stores_terms_in_segment_arena() {
        // Pin the arena-backed storage path on a worst-case LC: built
        // via incremental `add_term` calls, which used to leave one
        // owned Vec allocation per lc_map entry.
        let mut lc = LinearCombination::<Bn254Fr>::zero();
        for i in 0..5u64 {
            lc.add_term(Variable(i as usize + 1), FieldElement::<Bn254Fr>::one());
        }
        assert!(
            lc.terms_capacity() > lc.terms().len(),
            "precondition: incremental add_term leaves doubling slack"
        );

        let mut map: LcMap<Bn254Fr> = LcMap::new();
        map.insert(SsaVar(0), lc);

        let stored = map.get(&SsaVar(0)).expect("just inserted");
        assert_eq!(stored.terms().len(), 5);
        let segment = map.segments[0].as_ref().expect("segment allocated");
        assert_eq!(LcTag::from_slot(segment.slots[0]), LcTag::Terms);
        assert_eq!(segment.term_starts[0], 0);
        assert_eq!(segment.term_lens[0], 5);
        assert_eq!(segment.terms.len(), 5);
    }

    #[test]
    fn lc_map_stores_unit_variable_lcs_inline() {
        let mut map: LcMap<Bn254Fr> = LcMap::new();
        map.insert(
            SsaVar(0),
            LinearCombination::<Bn254Fr>::from_variable(Variable(7)),
        );

        assert!(matches!(
            map.get_entry(&SsaVar(0)),
            Some(LcMapEntry::Variable(Variable(7)))
        ));
        let restored = map.get(&SsaVar(0)).expect("just inserted");
        assert_eq!(restored.terms(), &[(Variable(7), FieldElement::ONE)]);
    }

    #[test]
    fn lc_map_insert_handles_empty_lc_without_regression() {
        // Empty `Vec::new()` has capacity 0; the conditional shrink
        // gate must skip the allocator round-trip and the slot must
        // still be populated.
        let lc = LinearCombination::<Bn254Fr>::zero();
        assert_eq!(lc.terms_capacity(), 0);
        assert_eq!(lc.terms().len(), 0);

        let mut map: LcMap<Bn254Fr> = LcMap::new();
        map.insert(SsaVar(0), lc);
        assert!(matches!(map.get_entry(&SsaVar(0)), Some(LcMapEntry::Zero)));
        assert!(map
            .get(&SsaVar(0))
            .expect("just inserted")
            .terms()
            .is_empty());
    }

    #[test]
    fn lc_map_streaming_path_pins_cap_eq_len_on_every_populated_slot() {
        // End-to-end version of the arena pin: feed a small IR
        // program through the same `compile_instructions_streaming`
        // entry that the boss-fight chunk-drain consumer hits, then
        // iterate every term slot in lc_map and assert the stored range
        // points into the owning segment's arena. Skips empty holes so the
        // pin also holds on the non-streaming path which may leave
        // sparse slots when upstream DCE drops instructions.
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v3,
            lhs: v2,
            rhs: v0,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v4,
            lhs: v3,
            rhs: v1,
        });

        let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
        compiler
            .compile_instructions_streaming(prog.iter().cloned())
            .unwrap();
        for (segment_idx, segment) in compiler.lc_map.segments.iter().enumerate() {
            if let Some(segment) = segment {
                for (offset, slot) in segment.slots.iter().enumerate() {
                    if LcTag::from_slot(*slot) == LcTag::Terms {
                        let idx = segment_idx * compiler.lc_map.segment_len + offset;
                        let payload = (*slot >> LcMapSegment::<Bn254Fr>::TAG_BITS) as usize;
                        let start = segment.term_starts[payload] as usize;
                        let len = segment.term_lens[payload] as usize;
                        assert!(len > 0, "lc_map slot {idx}: term range must be non-empty");
                        assert!(
                            start + len <= segment.terms.len(),
                            "lc_map slot {idx}: term range must stay inside segment arena"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn lc_map_compile_ir_path_pins_cap_eq_len_on_every_populated_slot() {
        // Cross-path coverage: same invariant, eager (non-streaming)
        // `compile_ir` entry. This is the legacy path that downstream
        // tooling (inspector, CLI provenance readers) still exercises.
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
        let a = prog.fresh_var();
        prog.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: IrVisibility::Witness,
        });
        let b = prog.fresh_var();
        prog.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: IrVisibility::Witness,
        });
        let s = prog.fresh_var();
        prog.push(Instruction::Add {
            result: s,
            lhs: a,
            rhs: b,
        });
        let p = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: p,
            lhs: s,
            rhs: a,
        });

        let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();
        for (segment_idx, segment) in compiler.lc_map.segments.iter().enumerate() {
            if let Some(segment) = segment {
                for (offset, slot) in segment.slots.iter().enumerate() {
                    if LcTag::from_slot(*slot) == LcTag::Terms {
                        let idx = segment_idx * compiler.lc_map.segment_len + offset;
                        let payload = (*slot >> LcMapSegment::<Bn254Fr>::TAG_BITS) as usize;
                        let start = segment.term_starts[payload] as usize;
                        let len = segment.term_lens[payload] as usize;
                        assert!(len > 0, "lc_map slot {idx}: term range must be non-empty");
                        assert!(
                            start + len <= segment.terms.len(),
                            "lc_map slot {idx}: term range must stay inside segment arena"
                        );
                    }
                }
            }
        }
    }
}
