use memory::Value;

/// Trait for garbage collection operations
pub trait GarbageCollector {
    fn collect_garbage(&mut self);
    fn mark_roots(&self) -> Vec<Value>;
}

impl GarbageCollector for super::vm::VM {
    fn collect_garbage(&mut self) {
        debug_assert!(
            !self.heap.is_gc_locked(),
            "GC triggered while GC lock is held"
        );
        let start = std::time::Instant::now();
        if self.stress_mode {
            println!("-- GC Triggered (Stress Mode) --");
        }

        let roots = self.mark_roots();
        self.heap.trace(roots);

        // CRITICAL: Mark Open Upvalues (GC Rooting Fix)
        // These are indices, so we must mark them manually in the heap set.
        let mut open_idx = self.open_upvalues;
        while let Some(idx) = open_idx {
            self.heap.mark_upvalue(idx);
            // Traverse list. If next is hidden in heap, retrieving it is safe
            // because we just marked 'idx' (it won't be swept).
            if let Some(upval) = self.heap.get_upvalue(idx) {
                open_idx = upval.next_open;
            } else {
                break;
            }
        }

        self.heap.sweep();
        // Threshold is set by sweep() with hysteresis — no override needed.

        let elapsed = start.elapsed().as_nanos() as u64;
        self.heap.stats.collections += 1;
        self.heap.stats.total_gc_time_ns += elapsed;
    }

    fn mark_roots(&self) -> Vec<Value> {
        let mut roots = Vec::new();

        // 1. Stack — only root the active region, not all 65K slots.
        //    Compute stack_top as max(frame.base + max_slots) across all frames.
        let mut stack_top = 0usize;
        for frame in &self.frames {
            if let Some(closure) = self.heap.get_closure(frame.closure) {
                if let Some(func) = self.heap.get_function(closure.function) {
                    stack_top = stack_top.max(frame.base + func.max_slots as usize);
                }
            }
        }
        roots.extend_from_slice(&self.stack[..stack_top]);

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
