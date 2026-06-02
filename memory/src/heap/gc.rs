use super::{
    objects::circom_handle_cost, CircomHandle, Closure, Function, Heap, IteratorObj, ProofObject,
    Upvalue, UpvalueLocation,
};
use crate::bigint::BigInt;
use crate::field::FieldElement;
use crate::Value;

/// Set a mark bit in a bitmap vec. Returns true if was previously unmarked.
/// Free function to enable split-borrow in `trace()` — takes `&mut Vec<u64>`
/// instead of `&mut Arena<T>`, allowing disjoint borrows of `data` and `free_set`.
#[inline]
fn bitmap_set(mark_bits: &mut Vec<u64>, idx: u32) -> bool {
    let word = (idx / 64) as usize;
    let bit = idx % 64;
    if word >= mark_bits.len() {
        mark_bits.resize(word + 1, 0);
    }
    let mask = 1u64 << bit;
    let was_unmarked = mark_bits[word] & mask == 0;
    mark_bits[word] |= mask;
    was_unmarked
}

impl Heap {
    // Tracing (Mark Phase) logic
    pub fn trace(&mut self, roots: Vec<Value>) {
        let mut worklist = roots;

        while let Some(val) = worklist.pop() {
            if !val.is_obj() {
                continue;
            }
            // `is_obj()` above guarantees `as_handle()` is `Some`. Use
            // `unwrap_or(0)` instead of `.unwrap()` so the tracer stays
            // panic-free even if a future refactor widens `is_obj()`
            // without updating this path; `handle=0` is a harmless
            // over-mark for the GC (bitmap_set is idempotent).
            let handle = val.as_handle().unwrap_or(0);

            match val.tag() {
                crate::value::TAG_STRING => {
                    bitmap_set(&mut self.strings.mark_bits, handle);
                }
                crate::value::TAG_LIST => {
                    if bitmap_set(&mut self.lists.mark_bits, handle) {
                        let h = handle as usize;
                        if h < self.lists.data.len() && !self.lists.free_set.contains(&handle) {
                            worklist.extend_from_slice(&self.lists.data[h]);
                        }
                    }
                }
                crate::value::TAG_FUNCTION => {
                    if bitmap_set(&mut self.functions.mark_bits, handle) {
                        let h = handle as usize;
                        if h < self.functions.data.len()
                            && !self.functions.free_set.contains(&handle)
                        {
                            worklist.extend_from_slice(&self.functions.data[h].constants);
                        }
                    }
                }
                crate::value::TAG_CLOSURE => {
                    if bitmap_set(&mut self.closures.mark_bits, handle) {
                        let h = handle as usize;
                        if h < self.closures.data.len() && !self.closures.free_set.contains(&handle)
                        {
                            let c = &self.closures.data[h];
                            worklist.push(Value::function(c.function));
                            for &up_idx in &c.upvalues {
                                if bitmap_set(&mut self.upvalues.mark_bits, up_idx) {
                                    let uh = up_idx as usize;
                                    if uh < self.upvalues.data.len()
                                        && !self.upvalues.free_set.contains(&up_idx)
                                    {
                                        if let UpvalueLocation::Closed(v) =
                                            self.upvalues.data[uh].location
                                        {
                                            worklist.push(v);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                crate::value::TAG_MAP => {
                    if bitmap_set(&mut self.maps.mark_bits, handle) {
                        let h = handle as usize;
                        if h < self.maps.data.len() && !self.maps.free_set.contains(&handle) {
                            for v in self.maps.data[h].values() {
                                worklist.push(*v);
                            }
                        }
                    }
                }
                crate::value::TAG_ITER => {
                    if bitmap_set(&mut self.iterators.mark_bits, handle) {
                        let h = handle as usize;
                        if h < self.iterators.data.len()
                            && !self.iterators.free_set.contains(&handle)
                        {
                            worklist.push(self.iterators.data[h].source);
                        }
                    }
                }
                crate::value::TAG_FIELD => {
                    bitmap_set(&mut self.fields.mark_bits, handle);
                }
                crate::value::TAG_PROOF => {
                    bitmap_set(&mut self.proofs.mark_bits, handle);
                }
                crate::value::TAG_BIGINT => {
                    bitmap_set(&mut self.bigints.mark_bits, handle);
                }
                crate::value::TAG_BYTES => {
                    bitmap_set(&mut self.bytes.mark_bits, handle);
                }
                crate::value::TAG_CIRCOM_HANDLE => {
                    // Leaf object — no nested Values to walk.
                    bitmap_set(&mut self.circom_handles.mark_bits, handle);
                }
                _ => {}
            }
        }
    }

    pub fn sweep(&mut self) {
        let mut freed_bytes: usize = 0;

        // Strings
        for i in 0..self.strings.data.len() {
            let idx = i as u32;
            if !self.strings.is_marked(idx) && !self.strings.is_free(idx) {
                self.strings.mark_free(idx);
                freed_bytes += self.strings.data[i].capacity();
                self.strings.data[i] = String::new();
            }
        }
        self.strings.clear_marks();

        // Lists
        for i in 0..self.lists.data.len() {
            let idx = i as u32;
            if !self.lists.is_marked(idx) && !self.lists.is_free(idx) {
                self.lists.mark_free(idx);
                freed_bytes += self.lists.data[i].capacity() * std::mem::size_of::<Value>();
                self.lists.data[i] = Vec::new();
            }
        }
        self.lists.clear_marks();

        // Functions
        for i in 0..self.functions.data.len() {
            let idx = i as u32;
            if !self.functions.is_marked(idx) && !self.functions.is_free(idx) {
                self.functions.mark_free(idx);
                let f = &self.functions.data[i];
                freed_bytes += f.chunk.capacity() * 4;
                freed_bytes += f.constants.capacity() * std::mem::size_of::<Value>();

                self.functions.data[i] = Function {
                    name: String::new(),
                    arity: 0,
                    max_slots: 0,
                    chunk: vec![],
                    constants: vec![],
                    upvalue_info: vec![],
                    line_info: vec![],
                };
            }
        }
        self.functions.clear_marks();

        // Closures
        for i in 0..self.closures.data.len() {
            let idx = i as u32;
            if !self.closures.is_marked(idx) && !self.closures.is_free(idx) {
                self.closures.mark_free(idx);
                let c = &self.closures.data[i];
                freed_bytes += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;

                self.closures.data[i] = Closure {
                    function: 0,
                    upvalues: vec![],
                };
            }
        }
        self.closures.clear_marks();

        // Upvalues
        for i in 0..self.upvalues.data.len() {
            let idx = i as u32;
            if !self.upvalues.is_marked(idx) && !self.upvalues.is_free(idx) {
                self.upvalues.mark_free(idx);
                freed_bytes += std::mem::size_of::<Upvalue>();

                self.upvalues.data[i] = Upvalue {
                    location: UpvalueLocation::Closed(Value::nil()),
                    next_open: None,
                };
            }
        }
        self.upvalues.clear_marks();

        // Iterators
        for i in 0..self.iterators.data.len() {
            let idx = i as u32;
            if !self.iterators.is_marked(idx) && !self.iterators.is_free(idx) {
                self.iterators.mark_free(idx);
                freed_bytes += std::mem::size_of::<IteratorObj>();
                self.iterators.data[i] = IteratorObj {
                    source: Value::nil(),
                    index: 0,
                };
            }
        }
        self.iterators.clear_marks();

        // Fields (leaf type, 32 bytes each)
        for i in 0..self.fields.data.len() {
            let idx = i as u32;
            if !self.fields.is_marked(idx) && !self.fields.is_free(idx) {
                self.fields.mark_free(idx);
                freed_bytes += std::mem::size_of::<FieldElement>();
                self.fields.data[i] = FieldElement::ZERO;
            }
        }
        self.fields.clear_marks();

        // Proofs
        for i in 0..self.proofs.data.len() {
            let idx = i as u32;
            if !self.proofs.is_marked(idx) && !self.proofs.is_free(idx) {
                self.proofs.mark_free(idx);
                let p = &self.proofs.data[i];
                freed_bytes += std::mem::size_of::<ProofObject>()
                    + p.proof_json.capacity()
                    + p.public_json.capacity()
                    + p.vkey_json.capacity();
                self.proofs.data[i] = ProofObject {
                    proof_json: String::new(),
                    public_json: String::new(),
                    vkey_json: String::new(),
                };
            }
        }
        self.proofs.clear_marks();

        // BigInts (leaf type)
        for i in 0..self.bigints.data.len() {
            let idx = i as u32;
            if !self.bigints.is_marked(idx) && !self.bigints.is_free(idx) {
                self.bigints.mark_free(idx);
                let bi = &self.bigints.data[i];
                freed_bytes += std::mem::size_of::<BigInt>() + std::mem::size_of_val(bi.limbs());
                self.bigints.data[i] = BigInt::zero(crate::bigint::BigIntWidth::W256);
            }
        }
        self.bigints.clear_marks();

        // Bytes (binary blobs, e.g. serialized ProveIR)
        for i in 0..self.bytes.data.len() {
            let idx = i as u32;
            if !self.bytes.is_marked(idx) && !self.bytes.is_free(idx) {
                self.bytes.mark_free(idx);
                freed_bytes += self.bytes.data[i].capacity();
                self.bytes.data[i] = Vec::new();
            }
        }
        self.bytes.clear_marks();

        // Circom handles (compile-time template call descriptors).
        for i in 0..self.circom_handles.data.len() {
            let idx = i as u32;
            if !self.circom_handles.is_marked(idx) && !self.circom_handles.is_free(idx) {
                self.circom_handles.mark_free(idx);
                freed_bytes += circom_handle_cost(&self.circom_handles.data[i]);
                self.circom_handles.data[i] = CircomHandle {
                    library_id: 0,
                    template_name: String::new(),
                    template_args: Vec::new(),
                };
            }
        }
        self.circom_handles.clear_marks();

        self.stats.total_freed_bytes += freed_bytes as u64;

        // Recompute bytes_allocated from surviving objects (self-correcting).
        // This eliminates drift from untracked mutations (push, insert, etc.)
        // at negligible cost — the sweep loop already touched every slot.
        self.bytes_allocated = self.recount_live_bytes();

        // Dynamic threshold with hysteresis to prevent GC thrashing.
        // Take the max of: 2× live heap, 1.5× previous threshold, and 1MB floor.
        let grow = self.bytes_allocated.saturating_mul(2);
        let hysteresis = self.next_gc_threshold.saturating_mul(3) / 2;
        self.next_gc_threshold = grow.max(hysteresis).max(1024 * 1024);
    }

    /// Recompute bytes_allocated by summing live object costs.
    /// Mirrors the per-type accounting in alloc_* / sweep.
    pub(super) fn recount_live_bytes(&self) -> usize {
        let mut total: usize = 0;
        for (i, s) in self.strings.data.iter().enumerate() {
            if !self.strings.is_free(i as u32) {
                total += s.capacity();
            }
        }
        for (i, l) in self.lists.data.iter().enumerate() {
            if !self.lists.is_free(i as u32) {
                total += l.capacity() * std::mem::size_of::<Value>();
            }
        }
        for (i, f) in self.functions.data.iter().enumerate() {
            if !self.functions.is_free(i as u32) {
                total += f.chunk.capacity() * 4;
                total += f.constants.capacity() * std::mem::size_of::<Value>();
            }
        }
        for (i, c) in self.closures.data.iter().enumerate() {
            if !self.closures.is_free(i as u32) {
                total += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;
            }
        }
        for (i, _) in self.upvalues.data.iter().enumerate() {
            if !self.upvalues.is_free(i as u32) {
                total += std::mem::size_of::<Upvalue>();
            }
        }
        for (i, _) in self.iterators.data.iter().enumerate() {
            if !self.iterators.is_free(i as u32) {
                total += std::mem::size_of::<IteratorObj>();
            }
        }
        for (i, _) in self.fields.data.iter().enumerate() {
            if !self.fields.is_free(i as u32) {
                total += std::mem::size_of::<FieldElement>();
            }
        }
        for (i, p) in self.proofs.data.iter().enumerate() {
            if !self.proofs.is_free(i as u32) {
                total += std::mem::size_of::<ProofObject>()
                    + p.proof_json.capacity()
                    + p.public_json.capacity()
                    + p.vkey_json.capacity();
            }
        }
        for (i, bi) in self.bigints.data.iter().enumerate() {
            if !self.bigints.is_free(i as u32) {
                total += std::mem::size_of::<BigInt>() + std::mem::size_of_val(bi.limbs());
            }
        }
        for (i, m) in self.maps.data.iter().enumerate() {
            if !self.maps.is_free(i as u32) {
                total += m.capacity() * Self::map_entry_size();
            }
        }
        for (i, b) in self.bytes.data.iter().enumerate() {
            if !self.bytes.is_free(i as u32) {
                total += b.capacity();
            }
        }
        for (i, ch) in self.circom_handles.data.iter().enumerate() {
            if !self.circom_handles.is_free(i as u32) {
                total += circom_handle_cost(ch);
            }
        }
        total
    }
}
