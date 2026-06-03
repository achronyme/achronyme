use super::*;

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
pub(super) enum LcMapEntry<F: FieldBackend> {
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
pub(super) enum LcTag {
    Empty = 0,
    Zero = 1,
    Variable = 2,
    Terms = 3,
}

impl LcTag {
    pub(super) fn from_slot(slot: u32) -> Self {
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
pub(super) struct LcMapSegment<F: FieldBackend> {
    pub(super) slots: Vec<u32>,
    pub(super) term_starts: Vec<u32>,
    pub(super) term_lens: Vec<u16>,
    pub(super) terms: Vec<(Variable, FieldElement<F>)>,
}

impl<F: FieldBackend> LcMapSegment<F> {
    pub(super) const TAG_BITS: u32 = 2;
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
pub(super) struct LcMap<F: FieldBackend> {
    pub(super) segments: Vec<Option<LcMapSegment<F>>>,
    pub(super) segment_len: usize,
    keep_last_vars: Option<usize>,
    keep_prefix_vars: usize,
    min_retained_idx: usize,
    pruned_segment_count: usize,
}

impl<F: FieldBackend> LcMap<F> {
    pub(super) const DEFAULT_SEGMENT_LEN: usize = 1 << 16;

    pub(super) fn new() -> Self {
        Self::with_segment_len(Self::DEFAULT_SEGMENT_LEN)
    }

    pub(super) fn with_segment_len(segment_len: usize) -> Self {
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

    pub(super) fn set_keep_last_vars(&mut self, keep_last_vars: Option<usize>) {
        self.keep_last_vars = keep_last_vars;
    }

    pub(super) fn set_keep_prefix_vars(&mut self, keep_prefix_vars: usize) {
        self.keep_prefix_vars = keep_prefix_vars;
    }

    pub(super) fn insert(&mut self, var: SsaVar, mut lc: LinearCombination<F>) {
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

    pub(super) fn get(&self, var: &SsaVar) -> Option<LinearCombination<F>> {
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
    pub(super) fn get_entry(&self, var: &SsaVar) -> Option<LcMapEntry<F>> {
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

    pub(super) fn clear(&mut self) {
        self.segments.clear();
        self.min_retained_idx = 0;
        self.pruned_segment_count = 0;
    }

    pub(super) fn shape_counts(&self) -> LcMapShapeCounts {
        let mut counts = LcMapShapeCounts::default();
        for segment in &self.segments {
            if let Some(segment) = segment {
                segment.shape_counts(&mut counts);
            }
        }
        counts
    }

    #[cfg(test)]
    pub(super) fn slot_count(&self) -> usize {
        self.segments
            .iter()
            .filter_map(Option::as_ref)
            .map(|segment| segment.slots.len())
            .sum()
    }

    #[cfg(test)]
    pub(super) fn allocated_segment_count(&self) -> usize {
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
pub(super) struct UsedSsaSet {
    segments: Vec<Option<Vec<usize>>>,
    segment_bits: usize,
    keep_last_vars: Option<usize>,
    keep_prefix_vars: usize,
    min_retained_idx: usize,
    pruned_segment_count: usize,
}

impl UsedSsaSet {
    const DEFAULT_SEGMENT_BITS: usize = 1 << 20;

    pub(super) fn new() -> Self {
        Self::with_segment_bits(Self::DEFAULT_SEGMENT_BITS)
    }

    pub(super) fn with_segment_bits(segment_bits: usize) -> Self {
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

    pub(super) fn set_keep_last_vars(&mut self, keep_last_vars: Option<usize>) {
        self.keep_last_vars = keep_last_vars;
    }

    pub(super) fn set_keep_prefix_vars(&mut self, keep_prefix_vars: usize) {
        self.keep_prefix_vars = keep_prefix_vars;
    }

    pub(super) fn mark(&mut self, var: SsaVar) {
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

    pub(super) fn contains(&self, var: SsaVar) -> bool {
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

    pub(super) fn clear(&mut self) {
        self.segments.clear();
        self.min_retained_idx = 0;
        self.pruned_segment_count = 0;
    }

    pub(super) fn word_count(&self) -> usize {
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
