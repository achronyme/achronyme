use crate::arena::Arena;
use crate::bigint::BigInt;
use crate::field::FieldElement;
use crate::Value;
use std::collections::HashMap;

/// Where an upvalue's value lives.
#[derive(Debug, Clone, Copy)]
pub enum UpvalueLocation {
    /// Index into the VM stack (open upvalue — variable still on the stack).
    Open(usize),
    /// Captured value (closed upvalue — variable has left the stack).
    Closed(Value),
}

#[derive(Debug, Clone)]
pub struct Upvalue {
    pub location: UpvalueLocation,
    pub next_open: Option<u32>, // Index into upvalues arena
}

#[derive(Debug, Clone)]
pub struct Closure {
    pub function: u32,
    pub upvalues: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub arity: u8,
    pub max_slots: u16, // <--- NEW: Peak register usage
    pub chunk: Vec<u32>,
    pub constants: Vec<Value>,
    // Upvalue rules (static analysis)
    // (is_local, index)
    // stored flat: [is_local_1, index_1, is_local_2, index_2...]
    pub upvalue_info: Vec<u8>,
    // Source line number for each bytecode instruction (1-based, 0 = unknown)
    pub line_info: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct IteratorObj {
    pub source: Value,
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct ProofObject {
    pub proof_json: String,
    pub public_json: String,
    pub vkey_json: String,
}

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

pub struct Heap {
    // Typed Arenas — pub(crate) to prevent external bypass of allocation tracking
    pub(crate) strings: Arena<String>,
    pub(crate) lists: Arena<Vec<Value>>,
    pub(crate) maps: Arena<HashMap<String, Value>>,
    pub(crate) functions: Arena<Function>,
    pub(crate) upvalues: Arena<Upvalue>,
    pub(crate) closures: Arena<Closure>,
    pub(crate) iterators: Arena<IteratorObj>,
    pub(crate) fields: Arena<FieldElement>,
    pub(crate) proofs: Arena<ProofObject>,
    pub(crate) bigints: Arena<BigInt>,

    // GC Metrics
    pub bytes_allocated: usize,
    pub next_gc_threshold: usize,
    pub request_gc: bool,
    gc_lock_depth: u32,
    pub max_heap_bytes: usize,
    pub heap_limit_exceeded: bool,
}

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

            bytes_allocated: 0,
            next_gc_threshold: 1024 * 1024, // Start at 1MB
            request_gc: false,
            gc_lock_depth: 0,
            max_heap_bytes: usize::MAX,
            heap_limit_exceeded: false,
        }
    }

    pub fn check_gc(&mut self) {
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

    pub fn alloc_upvalue(&mut self, val: Upvalue) -> u32 {
        self.bytes_allocated += std::mem::size_of::<Upvalue>();
        self.check_gc();
        self.upvalues.alloc(val)
    }

    pub fn get_upvalue(&self, index: u32) -> Option<&Upvalue> {
        self.upvalues.get(index)
    }

    pub fn get_upvalue_mut(&mut self, index: u32) -> Option<&mut Upvalue> {
        self.upvalues.get_mut(index)
    }

    pub fn alloc_closure(&mut self, c: Closure) -> u32 {
        self.bytes_allocated += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;
        self.check_gc();
        self.closures.alloc(c)
    }

    pub fn get_closure(&self, index: u32) -> Option<&Closure> {
        self.closures.get(index)
    }

    pub fn get_closure_mut(&mut self, index: u32) -> Option<&mut Closure> {
        self.closures.get_mut(index)
    }

    pub fn alloc_string(&mut self, s: String) -> u32 {
        self.bytes_allocated += s.capacity();
        self.check_gc();
        self.strings.alloc(s)
    }

    pub fn alloc_list(&mut self, l: Vec<Value>) -> u32 {
        self.bytes_allocated += l.capacity() * std::mem::size_of::<Value>();
        self.check_gc();
        self.lists.alloc(l)
    }

    pub fn alloc_map(&mut self, m: HashMap<String, Value>) -> u32 {
        self.bytes_allocated += m.capacity() * Self::map_entry_size();
        self.check_gc();
        self.maps.alloc(m)
    }

    pub fn get_map(&self, index: u32) -> Option<&HashMap<String, Value>> {
        self.maps.get(index)
    }

    pub fn get_map_mut(&mut self, index: u32) -> Option<&mut HashMap<String, Value>> {
        self.maps.get_mut(index)
    }

    /// Push a value onto a heap-allocated list, tracking capacity growth.
    pub fn list_push(&mut self, index: u32, value: Value) -> Option<()> {
        let list = self.lists.get_mut(index)?;
        let old_cap = list.capacity();
        list.push(value);
        let new_cap = list.capacity();
        if new_cap > old_cap {
            self.bytes_allocated += (new_cap - old_cap) * std::mem::size_of::<Value>();
            self.check_gc();
        }
        Some(())
    }

    /// Insert a key-value pair into a heap-allocated map, tracking capacity growth.
    pub fn map_insert(&mut self, index: u32, key: String, value: Value) -> Option<()> {
        let map = self.maps.get_mut(index)?;
        let old_cap = map.capacity();
        map.insert(key, value);
        let new_cap = map.capacity();
        if new_cap > old_cap {
            self.bytes_allocated += (new_cap - old_cap) * Self::map_entry_size();
            self.check_gc();
        }
        Some(())
    }

    /// Estimated cost per map entry (key + value + hash overhead).
    /// Used by both `alloc_map` and `recount_live_bytes` for consistency.
    fn map_entry_size() -> usize {
        std::mem::size_of::<String>() + std::mem::size_of::<Value>() + std::mem::size_of::<u64>()
    }

    // Tracing (Mark Phase) logic
    pub fn trace(&mut self, roots: Vec<Value>) {
        let mut worklist = roots;

        while let Some(val) = worklist.pop() {
            if !val.is_obj() {
                continue;
            }
            let handle = val.as_handle().unwrap();

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
                _ => {}
            }
        }
    }

    pub fn sweep(&mut self) {
        let mut _freed_bytes = 0;

        // Strings
        for i in 0..self.strings.data.len() {
            let idx = i as u32;
            if !self.strings.is_marked(idx) && !self.strings.is_free(idx) {
                self.strings.mark_free(idx);
                _freed_bytes += self.strings.data[i].capacity();
                self.strings.data[i] = String::new();
            }
        }
        self.strings.clear_marks();

        // Lists
        for i in 0..self.lists.data.len() {
            let idx = i as u32;
            if !self.lists.is_marked(idx) && !self.lists.is_free(idx) {
                self.lists.mark_free(idx);
                _freed_bytes += self.lists.data[i].capacity() * std::mem::size_of::<Value>();
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
                _freed_bytes += f.chunk.capacity() * 4;
                _freed_bytes += f.constants.capacity() * std::mem::size_of::<Value>();

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
                _freed_bytes += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;

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
                _freed_bytes += std::mem::size_of::<Upvalue>();

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
                _freed_bytes += std::mem::size_of::<IteratorObj>();
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
                _freed_bytes += std::mem::size_of::<FieldElement>();
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
                _freed_bytes += std::mem::size_of::<ProofObject>()
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
                _freed_bytes += std::mem::size_of::<BigInt>() + std::mem::size_of_val(bi.limbs());
                self.bigints.data[i] = BigInt::zero(crate::bigint::BigIntWidth::W256);
            }
        }
        self.bigints.clear_marks();

        // Recompute bytes_allocated from surviving objects (self-correcting).
        // This eliminates drift from untracked mutations (push, insert, etc.)
        // at negligible cost — the sweep loop already touched every slot.
        self.bytes_allocated = self.recount_live_bytes();

        // Dynamic threshold with hysteresis to prevent GC thrashing.
        // Take the max of: 2× live heap, 1.5× previous threshold, and 1MB floor.
        let grow = self.bytes_allocated * 2;
        let hysteresis = self.next_gc_threshold * 3 / 2;
        self.next_gc_threshold = grow.max(hysteresis).max(1024 * 1024);
    }

    /// Recompute bytes_allocated by summing live object costs.
    /// Mirrors the per-type accounting in alloc_* / sweep.
    fn recount_live_bytes(&self) -> usize {
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
        total
    }

    pub fn should_collect(&self) -> bool {
        self.bytes_allocated > self.next_gc_threshold
    }

    pub fn get_string(&self, index: u32) -> Option<&String> {
        self.strings.get(index)
    }

    pub fn get_list(&self, index: u32) -> Option<&Vec<Value>> {
        self.lists.get(index)
    }

    pub fn get_list_mut(&mut self, index: u32) -> Option<&mut Vec<Value>> {
        self.lists.get_mut(index)
    }

    pub fn alloc_function(&mut self, f: Function) -> u32 {
        self.bytes_allocated +=
            f.chunk.len() * 4 + f.constants.len() * std::mem::size_of::<Value>();
        self.check_gc();
        self.functions.alloc(f)
    }

    pub fn get_function(&self, index: u32) -> Option<&Function> {
        self.functions.get(index)
    }

    /// Replace the string arena wholesale with compiler output.
    ///
    /// # Safety invariant
    ///
    /// This invalidates **all** existing string handles. It must only be
    /// called during VM initialization, before `interpret()`. Any external
    /// string-handle caches (e.g. the VM's interner) must be cleared after
    /// this call.
    ///
    /// # Panics
    ///
    /// Panics if the string arena's free list is non-empty, which indicates
    /// that GC has already swept the arena (i.e. execution has started).
    pub fn import_strings(&mut self, strings: Vec<String>) {
        assert!(
            self.strings.free_indices.is_empty(),
            "import_strings called after execution started (string arena has freed slots)"
        );
        let cost: usize = strings.iter().map(|s| s.capacity()).sum();
        self.strings.data = strings;
        self.strings.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }

    pub fn alloc_iterator(&mut self, iter: IteratorObj) -> u32 {
        self.bytes_allocated += std::mem::size_of::<IteratorObj>();
        self.check_gc();
        self.iterators.alloc(iter)
    }

    pub fn get_iterator(&self, index: u32) -> Option<&IteratorObj> {
        self.iterators.get(index)
    }

    pub fn get_iterator_mut(&mut self, index: u32) -> Option<&mut IteratorObj> {
        self.iterators.get_mut(index)
    }

    pub fn import_fields(&mut self, fields: Vec<FieldElement>) -> Vec<u32> {
        let handles: Vec<u32> = fields.into_iter().map(|fe| self.alloc_field(fe)).collect();
        handles
    }

    pub fn alloc_field(&mut self, fe: FieldElement) -> u32 {
        self.bytes_allocated += std::mem::size_of::<FieldElement>();
        self.check_gc();
        self.fields.alloc(fe)
    }

    pub fn get_field(&self, index: u32) -> Option<&FieldElement> {
        self.fields.get(index)
    }

    pub fn alloc_proof(&mut self, p: ProofObject) -> u32 {
        self.bytes_allocated += std::mem::size_of::<ProofObject>()
            + p.proof_json.capacity()
            + p.public_json.capacity()
            + p.vkey_json.capacity();
        self.check_gc();
        self.proofs.alloc(p)
    }

    pub fn get_proof(&self, index: u32) -> Option<&ProofObject> {
        self.proofs.get(index)
    }

    pub fn alloc_bigint(&mut self, bi: BigInt) -> u32 {
        self.bytes_allocated += std::mem::size_of::<BigInt>() + std::mem::size_of_val(bi.limbs());
        self.check_gc();
        self.bigints.alloc(bi)
    }

    pub fn get_bigint(&self, index: u32) -> Option<&BigInt> {
        self.bigints.get(index)
    }

    pub fn get_bigint_mut(&mut self, index: u32) -> Option<&mut BigInt> {
        self.bigints.get_mut(index)
    }

    pub fn import_bigints(&mut self, bigints: Vec<BigInt>) -> Vec<u32> {
        bigints
            .into_iter()
            .map(|bi| self.alloc_bigint(bi))
            .collect()
    }
}
