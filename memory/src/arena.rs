use std::collections::HashSet;
use std::fmt;

/// Error returned when an arena allocation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaError {
    /// The arena has reached `u32::MAX` live entries.
    CapacityExceeded,
}

impl fmt::Display for ArenaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArenaError::CapacityExceeded => write!(f, "arena capacity exceeded u32::MAX"),
        }
    }
}

impl std::error::Error for ArenaError {}

/// Generic arena allocator with free-list recycling.
///
/// Stores values in a contiguous `Vec<T>` and recycles freed slots via
/// a free-list backed by a `HashSet` for O(1) membership queries.
#[derive(Debug, Clone)]
pub struct Arena<T> {
    pub(crate) data: Vec<T>,
    pub(crate) free_indices: Vec<u32>,
    /// O(1) membership mirror of `free_indices`. Invariant: contains the same
    /// elements as `free_indices` at all times. Maintained by `mark_free`,
    /// `reclaim_free`, and `clear_free` — direct mutation of `free_indices`
    /// without updating this set will break sweep correctness.
    pub(crate) free_set: HashSet<u32>,
    /// Bitmap for GC mark bits — 1 bit per slot. Lazily grown by `set_mark`.
    pub(crate) mark_bits: Vec<u64>,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arena<T> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            free_indices: Vec::new(),
            free_set: HashSet::new(),
            mark_bits: Vec::new(),
        }
    }

    /// O(1) check whether `idx` has been freed and is awaiting reuse.
    #[inline]
    pub fn is_free(&self, idx: u32) -> bool {
        self.free_set.contains(&idx)
    }

    /// Mark `idx` as free. Deduplicates: if already free, this is a no-op.
    /// O(1) amortized (HashSet insert + Vec push).
    pub fn mark_free(&mut self, idx: u32) {
        if self.free_set.insert(idx) {
            self.free_indices.push(idx);
        }
    }

    /// Pop a free index for reuse. Returns `None` if no free slots exist.
    /// O(1) amortized (Vec pop + HashSet remove).
    pub fn reclaim_free(&mut self) -> Option<u32> {
        let idx = self.free_indices.pop()?;
        self.free_set.remove(&idx);
        Some(idx)
    }

    /// Clear all free-tracking state. Used when replacing arena contents wholesale.
    pub fn clear_free(&mut self) {
        self.free_indices.clear();
        self.free_set.clear();
        self.mark_bits.clear();
    }

    /// Return a reference to the element at `idx`, or `None` if out of bounds or freed.
    #[inline]
    pub fn get(&self, idx: u32) -> Option<&T> {
        if self.is_free(idx) {
            return None;
        }
        self.data.get(idx as usize)
    }

    /// Fast unchecked access for objects known to be live (e.g. GC-rooted).
    ///
    /// Skips the `is_free` HashSet lookup — the caller **must** guarantee
    /// that `idx` refers to a live, reachable object (typically because it
    /// is rooted through the call-frame stack).
    ///
    /// # Safety
    ///
    /// - `idx` must be a valid index (< `self.data.len()`).
    /// - The slot at `idx` must not have been freed.
    #[inline(always)]
    pub unsafe fn get_unchecked_live(&self, idx: u32) -> &T {
        debug_assert!(
            (idx as usize) < self.data.len(),
            "get_unchecked_live: index {idx} out of bounds (len {})",
            self.data.len()
        );
        debug_assert!(
            !self.is_free(idx),
            "get_unchecked_live: index {idx} is freed"
        );
        self.data.get_unchecked(idx as usize)
    }

    /// Return a mutable reference to the element at `idx`, or `None` if out of bounds or freed.
    #[inline]
    pub fn get_mut(&mut self, idx: u32) -> Option<&mut T> {
        if self.is_free(idx) {
            return None;
        }
        self.data.get_mut(idx as usize)
    }

    /// Number of live (non-free) entries.
    pub fn live_count(&self) -> usize {
        self.data.len() - self.free_set.len()
    }

    /// Set mark bit. Returns true if was previously unmarked.
    #[inline]
    pub fn set_mark(&mut self, idx: u32) -> bool {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        if word >= self.mark_bits.len() {
            self.mark_bits.resize(word + 1, 0);
        }
        let mask = 1u64 << bit;
        let was_unmarked = self.mark_bits[word] & mask == 0;
        self.mark_bits[word] |= mask;
        was_unmarked
    }

    /// Check whether slot is marked.
    #[inline]
    pub fn is_marked(&self, idx: u32) -> bool {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        word < self.mark_bits.len() && self.mark_bits[word] & (1u64 << bit) != 0
    }

    /// Clear all mark bits. O(N/64) memset, preserves capacity.
    #[inline]
    pub fn clear_marks(&mut self) {
        self.mark_bits.iter_mut().for_each(|w| *w = 0);
    }

    /// Insert a value, reusing a freed slot if available, or appending.
    /// Returns `Err(ArenaError::CapacityExceeded)` if the arena grows beyond `u32::MAX` entries.
    pub fn alloc(&mut self, val: T) -> Result<u32, ArenaError> {
        if let Some(idx) = self.reclaim_free() {
            self.data[idx as usize] = val;
            Ok(idx)
        } else {
            let index = u32::try_from(self.data.len()).map_err(|_| ArenaError::CapacityExceeded)?;
            self.data.push(val);
            Ok(index)
        }
    }
}

#[cfg(test)]
mod bitmap_tests {
    use super::Arena;

    #[test]
    fn set_mark_returns_true_first_time() {
        let mut arena: Arena<u32> = Arena::new();
        arena.alloc(42).unwrap();
        assert!(arena.set_mark(0));
        assert!(!arena.set_mark(0)); // already marked
    }

    #[test]
    fn is_marked_after_set() {
        let mut arena: Arena<u32> = Arena::new();
        arena.alloc(1).unwrap();
        assert!(!arena.is_marked(0));
        arena.set_mark(0);
        assert!(arena.is_marked(0));
    }

    #[test]
    fn clear_marks_resets_all() {
        let mut arena: Arena<u32> = Arena::new();
        arena.alloc(1).unwrap();
        arena.alloc(2).unwrap();
        arena.set_mark(0);
        arena.set_mark(1);
        arena.clear_marks();
        assert!(!arena.is_marked(0));
        assert!(!arena.is_marked(1));
    }

    #[test]
    fn mark_high_index_grows_bitmap() {
        let mut arena: Arena<u32> = Arena::new();
        for i in 0..200 {
            arena.alloc(i).unwrap();
        }
        assert!(arena.set_mark(199));
        assert!(arena.is_marked(199));
        assert!(!arena.is_marked(198));
    }

    #[test]
    fn is_marked_out_of_range() {
        let arena: Arena<u32> = Arena::new();
        assert!(!arena.is_marked(9999));
    }

    #[test]
    fn clear_marks_preserves_capacity() {
        let mut arena: Arena<u32> = Arena::new();
        for i in 0..100 {
            arena.alloc(i).unwrap();
        }
        arena.set_mark(99);
        let cap_before = arena.mark_bits.capacity();
        arena.clear_marks();
        assert_eq!(arena.mark_bits.capacity(), cap_before);
    }
}
