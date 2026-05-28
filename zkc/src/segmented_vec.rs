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
//! API surface is intentionally minimal — `push`, `len`, `iter`,
//! `iter_mut`, `retain`, `clear`, `Clone` — matching exactly the
//! operations the `witness_ops` consumers actually use. No indexed
//! access is exposed; callers that need `IndexMut` (e.g. R1CS
//! constraint-vector mutation) want a different wrapper with uniform
//! segment sizes for the `i >> log2_seg, i & mask` math.

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
}
