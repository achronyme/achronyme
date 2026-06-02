use super::{GcStats, Heap};
use crate::arena::Arena;

impl Default for Heap {
    fn default() -> Self {
        Self::new()
    }
}

impl Heap {
    pub fn new() -> Self {
        Self {
            strings: Arena::new(),
            lists: Arena::new(),
            maps: Arena::new(),
            functions: Arena::new(),
            upvalues: Arena::new(),
            closures: Arena::new(),
            iterators: Arena::new(),
            fields: Arena::new(),
            proofs: Arena::new(),
            bigints: Arena::new(),
            bytes: Arena::new(),
            circom_handles: Arena::new(),

            bytes_allocated: 0,
            next_gc_threshold: 1024 * 1024, // Start at 1MB
            request_gc: false,
            gc_lock_depth: 0,
            max_heap_bytes: usize::MAX,
            heap_limit_exceeded: false,
            stats: GcStats::default(),
        }
    }

    pub fn check_gc(&mut self) {
        if self.bytes_allocated > self.stats.peak_heap_bytes {
            self.stats.peak_heap_bytes = self.bytes_allocated;
        }
        if self.gc_lock_depth == 0 && self.bytes_allocated > self.next_gc_threshold {
            self.request_gc = true;
        }
        if self.bytes_allocated > self.max_heap_bytes {
            self.heap_limit_exceeded = true;
        }
    }

    /// Prevent `check_gc()` from requesting a GC cycle.
    /// Supports reentrant (nested) locking via a depth counter.
    pub fn lock_gc(&mut self) {
        self.gc_lock_depth += 1;
    }

    /// Re-enable GC requests when the outermost lock is released.
    /// Calls `check_gc()` on full unlock to catch deferred threshold crossings.
    pub fn unlock_gc(&mut self) {
        debug_assert!(
            self.gc_lock_depth > 0,
            "unlock_gc called without matching lock_gc"
        );
        self.gc_lock_depth -= 1;
        if self.gc_lock_depth == 0 {
            self.check_gc();
        }
    }

    /// Returns whether the GC is currently locked.
    pub fn is_gc_locked(&self) -> bool {
        self.gc_lock_depth > 0
    }

    /// Mark an upvalue index as reachable (for open upvalue rooting in GC).
    pub fn mark_upvalue(&mut self, idx: u32) {
        self.upvalues.set_mark(idx);
    }

    /// Returns true if the proofs arena has any live entries.
    pub fn has_proofs(&self) -> bool {
        self.proofs.live_count() > 0
    }

    /// Query whether a string slot has been freed (for testing).
    pub fn is_string_free(&self, idx: u32) -> bool {
        self.strings.is_free(idx)
    }

    /// Query whether a list slot has been freed (for testing).
    pub fn is_list_free(&self, idx: u32) -> bool {
        self.lists.is_free(idx)
    }

    /// Query whether a list index is marked as reachable (for testing).
    pub fn is_list_marked(&self, idx: u32) -> bool {
        self.lists.is_marked(idx)
    }

    pub fn should_collect(&self) -> bool {
        self.bytes_allocated > self.next_gc_threshold
    }
}
