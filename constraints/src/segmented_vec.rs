//! Append-only segmented sequence container with bounded per-allocation
//! size.
//!
//! [`SegmentedVec<T>`] stores elements across a chain of inner `Vec<T>`
//! segments rather than a single backing buffer. The standard
//! `Vec<T>::push` growth strategy doubles capacity when full, so a
//! container of N elements needs a contiguous allocation of `2 * N *
//! size_of::<T>()` bytes at the doubling threshold. For the R1CS
//! compiler's `witness_ops` log on million-constraint circuits, that
//! single-allocation request can exceed a constrained address space
//! (an embedded sandbox, a memory-limited builder host) even when the
//! total resident set is well within budget — the failure mode is
//! "no contiguous block large enough", not "out of total memory".
//!
//! This wrapper sidesteps that failure by capping each inner segment
//! at [`SegmentedVec::DEFAULT_SEGMENT_MAX`] elements. Once a segment
//! reaches that cap it is sealed, and the next push starts a fresh
//! segment pre-allocated at the cap. Worst-case single allocation is
//! `SEGMENT_MAX * size_of::<T>()`, independent of total length.
//!
//! The first segment is allowed to grow naturally via standard `Vec`
//! doubling so small consumers don't pay a 64 MB up-front cost for a
//! handful of items.
//!
//! API surface covers the operations both `witness_ops` (append-only
//! with `retain` for substitution-pass compaction) and the R1CS
//! `ConstraintSystem.constraints` (full `Index`/`IndexMut` for the
//! linear-elimination + DEDUCE rewrites) need.

/// An append-only sequence whose backing storage is sliced into
/// bounded segments to avoid large single-allocation requests.
#[derive(Debug)]
pub struct SegmentedVec<T> {
    segments: Vec<Vec<T>>,
    segment_max: usize,
    len: usize,
}

impl<T> SegmentedVec<T> {
    /// Default cap on individual segment length. Chosen so that for a
    /// 64-byte element (R1CS `WitnessOp<F>`) one segment fits in
    /// roughly 64 MB — comfortably under any practical sandbox.
    pub const DEFAULT_SEGMENT_MAX: usize = 1 << 20;

    /// Construct an empty container with the default segment cap.
    pub fn new() -> Self {
        Self::with_segment_max(Self::DEFAULT_SEGMENT_MAX)
    }

    /// Construct an empty container with a custom segment cap. Useful
    /// for tests that need to exercise the segment boundary with a
    /// small `N`, and for callers tuning the allocation budget per
    /// element type.
    pub fn with_segment_max(segment_max: usize) -> Self {
        assert!(segment_max > 0, "segment cap must be positive");
        Self {
            segments: Vec::new(),
            segment_max,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append `item`. If the last segment has room (`len < segment_max`)
    /// the push lands there; otherwise a fresh segment pre-allocated at
    /// `segment_max` is opened. The very first segment is allowed to
    /// grow via standard `Vec` doubling so small consumers don't pay
    /// the full pre-allocation cost up front.
    pub fn push(&mut self, item: T) {
        if let Some(last) = self.segments.last_mut() {
            if last.len() < self.segment_max {
                last.push(item);
                self.len += 1;
                return;
            }
        }
        let cap = if self.segments.is_empty() {
            0
        } else {
            self.segment_max
        };
        let mut new_seg = Vec::with_capacity(cap);
        new_seg.push(item);
        self.segments.push(new_seg);
        self.len += 1;
    }

    /// Drop every segment and reset length to zero.
    pub fn clear(&mut self) {
        self.segments.clear();
        self.len = 0;
    }

    /// Shorten the container to `new_len`, dropping any elements past
    /// the new boundary. If `new_len >= len()` this is a no-op (matches
    /// `Vec::truncate` semantics). Empty trailing segments are dropped
    /// so iteration doesn't pay for them.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        // Walk segments in order, dropping elements until cumulative
        // length matches `new_len`.
        let mut remaining = new_len;
        let mut last_kept = 0usize;
        for (i, seg) in self.segments.iter_mut().enumerate() {
            if remaining >= seg.len() {
                remaining -= seg.len();
                last_kept = i + 1;
            } else {
                seg.truncate(remaining);
                last_kept = if remaining == 0 { i } else { i + 1 };
                break;
            }
        }
        self.segments.truncate(last_kept);
        self.len = new_len;
    }

    /// Iterate elements in insertion order across all segments.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.segments.iter().flat_map(|s| s.iter())
    }

    /// Mutably iterate elements in insertion order across all segments.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.segments.iter_mut().flat_map(|s| s.iter_mut())
    }

    /// Retain only elements satisfying `predicate`, preserving order.
    /// Each segment is filtered in place; segments that empty out are
    /// dropped so a subsequent iteration doesn't pay for them.
    pub fn retain<P>(&mut self, mut predicate: P)
    where
        P: FnMut(&T) -> bool,
    {
        for seg in &mut self.segments {
            seg.retain(&mut predicate);
        }
        self.segments.retain(|s| !s.is_empty());
        self.len = self.segments.iter().map(|s| s.len()).sum();
    }

    /// Number of segments currently allocated. Visible for tests
    /// that pin the segment-boundary behavior.
    #[doc(hidden)]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Map a flat index into `(segment_index, slot_index)`. The first
    /// segment grows naturally via `Vec` doubling so its length is
    /// runtime-dependent; segments 1.. are uniform at `segment_max`.
    /// O(1) — only segment 0 is irregular.
    #[inline]
    fn locate(&self, idx: usize) -> (usize, usize) {
        let first_len = self.segments.first().map(|s| s.len()).unwrap_or(0);
        if idx < first_len {
            return (0, idx);
        }
        let rest = idx - first_len;
        (1 + rest / self.segment_max, rest % self.segment_max)
    }

    /// Swap the elements at indices `i` and `j`. Like `Vec::swap`,
    /// panics if either index is out of bounds. Handles cross-segment
    /// swaps by routing through disjoint borrows of the two segments.
    pub fn swap(&mut self, i: usize, j: usize) {
        assert!(i < self.len, "index out of bounds: i={i}, len={}", self.len);
        assert!(j < self.len, "index out of bounds: j={j}, len={}", self.len);
        if i == j {
            return;
        }
        let (si, oi) = self.locate(i);
        let (sj, oj) = self.locate(j);
        if si == sj {
            self.segments[si].swap(oi, oj);
            return;
        }
        let (lo, hi) = if si < sj { (si, sj) } else { (sj, si) };
        let (lo_slot, hi_slot) = if si < sj { (oi, oj) } else { (oj, oi) };
        let (left, right) = self.segments.split_at_mut(hi);
        std::mem::swap(&mut left[lo][lo_slot], &mut right[0][hi_slot]);
    }
}

impl<T> std::ops::Index<usize> for SegmentedVec<T> {
    type Output = T;
    #[inline]
    fn index(&self, idx: usize) -> &T {
        assert!(idx < self.len, "index out of bounds: {idx} >= {}", self.len);
        let (seg, slot) = self.locate(idx);
        &self.segments[seg][slot]
    }
}

impl<T> std::ops::IndexMut<usize> for SegmentedVec<T> {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut T {
        assert!(idx < self.len, "index out of bounds: {idx} >= {}", self.len);
        let (seg, slot) = self.locate(idx);
        &mut self.segments[seg][slot]
    }
}

impl<T> Default for SegmentedVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for SegmentedVec<T> {
    fn clone(&self) -> Self {
        Self {
            segments: self.segments.clone(),
            segment_max: self.segment_max,
            len: self.len,
        }
    }
}

impl<'a, T> IntoIterator for &'a SegmentedVec<T> {
    type Item = &'a T;
    type IntoIter = std::iter::FlatMap<
        std::slice::Iter<'a, Vec<T>>,
        std::slice::Iter<'a, T>,
        fn(&'a Vec<T>) -> std::slice::Iter<'a, T>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter().flat_map(|s| s.iter())
    }
}

impl<T> Extend<T> for SegmentedVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.push(item);
        }
    }
}

impl<T> FromIterator<T> for SegmentedVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut v = SegmentedVec::new();
        v.extend(iter);
        v
    }
}

impl<T> IntoIterator for SegmentedVec<T> {
    type Item = T;
    type IntoIter = std::iter::FlatMap<
        std::vec::IntoIter<Vec<T>>,
        std::vec::IntoIter<T>,
        fn(Vec<T>) -> std::vec::IntoIter<T>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.segments
            .into_iter()
            .flat_map(|s: Vec<T>| -> std::vec::IntoIter<T> { s.into_iter() })
    }
}

impl<'a, T> IntoIterator for &'a mut SegmentedVec<T> {
    type Item = &'a mut T;
    type IntoIter = std::iter::FlatMap<
        std::slice::IterMut<'a, Vec<T>>,
        std::slice::IterMut<'a, T>,
        fn(&'a mut Vec<T>) -> std::slice::IterMut<'a, T>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter_mut().flat_map(|s| s.iter_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_is_consistent() {
        let v: SegmentedVec<u32> = SegmentedVec::new();
        assert_eq!(v.len(), 0);
        assert!(v.is_empty());
        assert_eq!(v.segment_count(), 0);
        assert_eq!(v.iter().count(), 0);
    }

    #[test]
    fn default_first_segment_starts_empty() {
        // Pins the natural-growth-of-first-segment design: a fresh
        // SegmentedVec must not have allocated any segment yet, so
        // workspace tests that build many R1CSCompiler instances do
        // not each pay an up-front per-segment pre-allocation cost.
        let v: SegmentedVec<u32> = SegmentedVec::new();
        assert_eq!(v.segment_count(), 0);
    }

    #[test]
    fn push_grows_first_segment_naturally() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        v.push(1);
        v.push(2);
        v.push(3);
        assert_eq!(v.len(), 3);
        assert_eq!(v.segment_count(), 1);
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn push_exactly_at_segment_boundary_keeps_one_segment() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..4 {
            v.push(i);
        }
        assert_eq!(v.len(), 4);
        assert_eq!(v.segment_count(), 1);
    }

    #[test]
    fn push_past_segment_boundary_opens_new_segment() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..5 {
            v.push(i);
        }
        assert_eq!(v.len(), 5);
        assert_eq!(v.segment_count(), 2);
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn iteration_order_matches_insertion_across_many_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..10 {
            v.push(i);
        }
        assert_eq!(v.len(), 10);
        assert_eq!(v.segment_count(), 4);
        assert_eq!(
            v.iter().copied().collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn iter_mut_modifies_in_place_across_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..7 {
            v.push(i);
        }
        for x in v.iter_mut() {
            *x *= 10;
        }
        assert_eq!(
            v.iter().copied().collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60]
        );
    }

    #[test]
    fn retain_drops_filtered_and_compacts_empty_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..9 {
            v.push(i);
        }
        assert_eq!(v.segment_count(), 3);
        v.retain(|x| *x % 2 == 0);
        assert_eq!(v.len(), 5);
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn retain_dropping_a_whole_segment_compacts_to_fewer_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        // Segment 0: [0, 1, 2], Segment 1: [3, 4, 5], Segment 2: [6, 7, 8]
        for i in 0..9 {
            v.push(i);
        }
        // Drop the middle segment by retaining only values < 3 or >= 6.
        v.retain(|x| *x < 3 || *x >= 6);
        assert_eq!(v.len(), 6);
        assert_eq!(v.segment_count(), 2);
        assert_eq!(
            v.iter().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 6, 7, 8]
        );
    }

    #[test]
    fn clear_drops_all_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..7 {
            v.push(i);
        }
        v.clear();
        assert_eq!(v.len(), 0);
        assert!(v.is_empty());
        assert_eq!(v.segment_count(), 0);
        v.push(42);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn clone_preserves_segments_and_data() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..8 {
            v.push(i);
        }
        let cloned = v.clone();
        assert_eq!(cloned.len(), v.len());
        assert_eq!(cloned.segment_count(), v.segment_count());
        assert_eq!(
            cloned.iter().copied().collect::<Vec<_>>(),
            v.iter().copied().collect::<Vec<_>>()
        );
    }

    #[test]
    fn into_iter_for_reference_works_in_for_loop() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(3);
        for i in 0..7 {
            v.push(i);
        }
        let mut sum = 0u32;
        for x in &v {
            sum += *x;
        }
        assert_eq!(sum, (0..7u32).sum::<u32>());
    }

    #[test]
    fn second_segment_is_preallocated_to_segment_max() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..5 {
            v.push(i);
        }
        // First segment grew naturally; second segment was opened by
        // overflow and must be pre-allocated at segment_max so further
        // pushes inside it don't trigger Vec doubling beyond the cap.
        let second_seg_cap = v.segments[1].capacity();
        assert_eq!(second_seg_cap, 4);
    }

    #[test]
    fn index_returns_correct_element_across_segment_boundary() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(8);
        for i in 0..25 {
            v.push(i);
        }
        assert_eq!(v[0], 0);
        assert_eq!(v[7], 7);
        assert_eq!(v[8], 8);
        assert_eq!(v[15], 15);
        assert_eq!(v[16], 16);
        assert_eq!(v[24], 24);
    }

    #[test]
    fn index_mut_writes_propagate() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..10 {
            v.push(i);
        }
        v[7] = 999;
        v[2] = 111;
        assert_eq!(v[7], 999);
        assert_eq!(v[2], 111);
        let collected: Vec<u32> = v.iter().copied().collect();
        assert_eq!(collected, vec![0, 1, 111, 3, 4, 5, 6, 999, 8, 9]);
    }

    #[test]
    fn swap_across_segments_exchanges_values() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..12 {
            v.push(i);
        }
        // First seg grows naturally to 4 (it filled and overflow opened
        // segment 1), so segment 0 holds [0,1,2,3] and segment 1 holds
        // [4,5,6,7]; swap across that boundary.
        v.swap(2, 9);
        assert_eq!(v[2], 9);
        assert_eq!(v[9], 2);
    }

    #[test]
    fn swap_within_segment_exchanges_values() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..8 {
            v.push(i);
        }
        v.swap(0, 3);
        assert_eq!(v[0], 3);
        assert_eq!(v[3], 0);
        v.swap(5, 6);
        assert_eq!(v[5], 6);
        assert_eq!(v[6], 5);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn index_out_of_bounds_panics() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..5 {
            v.push(i);
        }
        let _ = v[100];
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn swap_out_of_bounds_panics() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..5 {
            v.push(i);
        }
        v.swap(2, 100);
    }

    #[test]
    fn truncate_within_a_segment_keeps_outer_segments_intact() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..10 {
            v.push(i);
        }
        // Segments: [0,1,2,3] [4,5,6,7] [8,9]; truncate to 6 should
        // leave [0,1,2,3] [4,5] in two segments.
        v.truncate(6);
        assert_eq!(v.len(), 6);
        assert_eq!(v.segment_count(), 2);
        assert_eq!(
            v.iter().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn truncate_drops_whole_trailing_segments() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        for i in 0..10 {
            v.push(i);
        }
        v.truncate(4);
        assert_eq!(v.len(), 4);
        assert_eq!(v.segment_count(), 1);
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn extend_appends_iterator_items() {
        let mut v: SegmentedVec<u32> = SegmentedVec::with_segment_max(4);
        v.push(0);
        v.extend(vec![1, 2, 3, 4, 5]);
        assert_eq!(v.len(), 6);
        assert_eq!(
            v.iter().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5]
        );
        // Confirms segment cap routing: 6 items at cap=4 → 2 segments.
        assert_eq!(v.segment_count(), 2);
    }
}
