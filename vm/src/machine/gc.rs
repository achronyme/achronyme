use memory::Value;

/// Trait for garbage collection operations
pub trait GarbageCollector {
    fn collect_garbage(&mut self);
    fn mark_roots(&self) -> Vec<Value>;
}

impl GarbageCollector for super::vm::VM {
    fn collect_garbage(&mut self) {
        let _before = self.heap.bytes_allocated;
        // println!("-- GC Begin (Allocated: {} bytes) --", before);

        let roots = self.mark_roots();
        self.heap.trace(roots);
        self.heap.sweep();

        // Dynamic Threshold: Double it or set reasonable limits
        self.heap.next_gc_threshold = std::cmp::max(
            self.heap.bytes_allocated * 2,
            1024 * 1024, // Min 1MB
        );
    }

    fn mark_roots(&self) -> Vec<Value> {
        let mut roots = Vec::new();

        // 1. Stack
        roots.extend_from_slice(&self.stack);

        // 2. Globals
        for entry in self.globals.values() {
            roots.push(entry.value);
        }

        // 3. Call Frames (Closures/Functions)
        for frame in &self.frames {
            roots.push(Value::function(frame.closure));
        }

        roots
    }
}
