use memory::Value;

/// Trait for garbage collection operations
pub trait GarbageCollector {
    fn collect_garbage(&mut self);
    fn mark_roots(&self) -> Vec<Value>;
}

impl GarbageCollector for super::vm::VM {
    fn collect_garbage(&mut self) {
        let _before = self.heap.bytes_allocated;
        if self.stress_mode {
            println!("-- GC Triggered (Stress Mode) --");
        } else {
             // println!("-- GC Begin (Allocated: {} bytes) --", _before);
        }

        let roots = self.mark_roots();
        self.heap.trace(roots);

        // CRITICAL: Mark Open Upvalues (GC Rooting Fix)
        // These are indices, so we must mark them manually in the heap set.
        let mut open_idx = self.open_upvalues;
        while let Some(idx) = open_idx {
            if !self.heap.marked_upvalues.contains(&idx) {
                self.heap.marked_upvalues.insert(idx);
            }
            // Traverse list. If next is hidden in heap, retrieving it is safe 
            // because we just marked 'idx' (it won't be swept).
             if let Some(upval) = self.heap.get_upvalue(idx) {
                open_idx = upval.next_open;
            } else {
                break;
            }
        }

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
        for entry in &self.globals {
            roots.push(entry.value);
        }

        // 3. Call Frames (Closures)
        for frame in &self.frames {
            roots.push(Value::closure(frame.closure));
        }

        // 4. Prototypes (compiled function templates)
        for &proto_idx in &self.prototypes {
            roots.push(Value::function(proto_idx));
        }

        roots
    }
}
