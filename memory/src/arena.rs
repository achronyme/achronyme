use std::collections::HashSet;

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
    free_set: HashSet<u32>,
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
    }

    /// Return a reference to the element at `idx`, or `None` if out of bounds or freed.
    #[inline]
    pub fn get(&self, idx: u32) -> Option<&T> {
        if self.is_free(idx) {
            return None;
        }
        self.data.get(idx as usize)
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

    /// Insert a value, reusing a freed slot if available, or appending.
    /// Panics if the arena grows beyond `u32::MAX` entries.
    pub fn alloc(&mut self, val: T) -> u32 {
        if let Some(idx) = self.reclaim_free() {
            self.data[idx as usize] = val;
            idx
        } else {
            let index = u32::try_from(self.data.len())
                .unwrap_or_else(|_| panic!("arena capacity exceeded u32::MAX"));
            self.data.push(val);
            index
        }
    }
}
