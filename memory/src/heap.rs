use crate::arena::Arena;
use crate::bigint::BigInt;
use crate::field::FieldElement;
use crate::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct GcStats {
    pub collections: u64,
    pub total_freed_bytes: u64,
    pub peak_heap_bytes: usize,
    pub total_gc_time_ns: u64,
}

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

/// Compile-time circom template call descriptor, stored in the
/// heap's `circom_handles` arena and referenced from user code via
/// `Value::circom_handle(idx)`.
///
/// The handle is a leaf object — it does not reference any other
/// `Value`, so GC tracing just marks its slot. The real
/// [`circom::CircomLibrary`] is owned by the VM's `circom_handler`
/// (a trait object injected at program-run time), not by the heap,
/// so this struct never holds a direct reference into it. The
/// `library_id` field selects which library the handler should use
/// at dispatch time.
///
/// `template_args` stores the pre-evaluated compile-time template
/// parameters as u64 values — they were required to reduce to
/// `CircuitExpr::Const` at compile time, which for real-world circom
/// use cases (array lengths, iteration counts, etc.) always fits in
/// a u64.
#[derive(Debug, Clone)]
pub struct CircomHandle {
    pub library_id: u32,
    pub template_name: String,
    pub template_args: Vec<u64>,
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
    pub(crate) bytes: Arena<Vec<u8>>,
    pub(crate) circom_handles: Arena<CircomHandle>,

    // GC Metrics
    pub bytes_allocated: usize,
    pub next_gc_threshold: usize,
    pub request_gc: bool,
    gc_lock_depth: u32,
    pub max_heap_bytes: usize,
    pub heap_limit_exceeded: bool,
    pub stats: GcStats,
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

    pub fn alloc_upvalue(&mut self, val: Upvalue) -> Result<u32, crate::arena::ArenaError> {
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

    pub fn alloc_closure(&mut self, c: Closure) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;
        self.check_gc();
        self.closures.alloc(c)
    }

    pub fn get_closure(&self, index: u32) -> Option<&Closure> {
        self.closures.get(index)
    }

    /// # Safety
    /// `index` must refer to a live (GC-rooted) closure.
    #[inline(always)]
    pub unsafe fn get_closure_unchecked(&self, index: u32) -> &Closure {
        self.closures.get_unchecked_live(index)
    }

    pub fn get_closure_mut(&mut self, index: u32) -> Option<&mut Closure> {
        self.closures.get_mut(index)
    }

    pub fn alloc_string(&mut self, s: String) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += s.capacity();
        self.check_gc();
        self.strings.alloc(s)
    }

    pub fn alloc_list(&mut self, l: Vec<Value>) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += l.capacity() * std::mem::size_of::<Value>();
        self.check_gc();
        self.lists.alloc(l)
    }

    pub fn alloc_map(
        &mut self,
        m: HashMap<String, Value>,
    ) -> Result<u32, crate::arena::ArenaError> {
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

    pub fn alloc_function(&mut self, f: Function) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated +=
            f.chunk.len() * 4 + f.constants.len() * std::mem::size_of::<Value>();
        self.check_gc();
        self.functions.alloc(f)
    }

    pub fn get_function(&self, index: u32) -> Option<&Function> {
        self.functions.get(index)
    }

    /// # Safety
    /// `index` must refer to a live (GC-reachable) function.
    #[inline(always)]
    pub unsafe fn get_function_unchecked(&self, index: u32) -> &Function {
        self.functions.get_unchecked_live(index)
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

    pub fn alloc_iterator(&mut self, iter: IteratorObj) -> Result<u32, crate::arena::ArenaError> {
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

    pub fn import_fields(
        &mut self,
        fields: Vec<FieldElement>,
    ) -> Result<Vec<u32>, crate::arena::ArenaError> {
        fields.into_iter().map(|fe| self.alloc_field(fe)).collect()
    }

    pub fn alloc_field(&mut self, fe: FieldElement) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<FieldElement>();
        self.check_gc();
        self.fields.alloc(fe)
    }

    pub fn get_field(&self, index: u32) -> Option<&FieldElement> {
        self.fields.get(index)
    }

    pub fn alloc_proof(&mut self, p: ProofObject) -> Result<u32, crate::arena::ArenaError> {
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

    pub fn alloc_bigint(&mut self, bi: BigInt) -> Result<u32, crate::arena::ArenaError> {
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

    pub fn import_bigints(
        &mut self,
        bigints: Vec<BigInt>,
    ) -> Result<Vec<u32>, crate::arena::ArenaError> {
        bigints
            .into_iter()
            .map(|bi| self.alloc_bigint(bi))
            .collect()
    }

    pub fn alloc_bytes(&mut self, data: Vec<u8>) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += data.capacity();
        self.check_gc();
        self.bytes.alloc(data)
    }

    pub fn get_bytes(&self, index: u32) -> Option<&Vec<u8>> {
        self.bytes.get(index)
    }

    /// Bulk-import byte blobs from the compiler (same pattern as import_strings).
    pub fn import_bytes(&mut self, blobs: Vec<Vec<u8>>) {
        assert!(
            self.bytes.free_indices.is_empty(),
            "import_bytes called after execution started (bytes arena has freed slots)"
        );
        let cost: usize = blobs.iter().map(|b| b.capacity()).sum();
        self.bytes.data = blobs;
        self.bytes.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }

    pub fn alloc_circom_handle(
        &mut self,
        handle: CircomHandle,
    ) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += circom_handle_cost(&handle);
        self.check_gc();
        self.circom_handles.alloc(handle)
    }

    pub fn get_circom_handle(&self, index: u32) -> Option<&CircomHandle> {
        self.circom_handles.get(index)
    }

    /// Bulk-import circom handles from the compiler's handle table
    /// (same pattern as `import_bytes`). Called by the VM's bytecode
    /// loader at program-load time so every `Value::circom_handle(i)`
    /// constant resolves against the same arena slot the compiler
    /// allocated at compile time.
    pub fn import_circom_handles(&mut self, handles: Vec<CircomHandle>) {
        assert!(
            self.circom_handles.free_indices.is_empty(),
            "import_circom_handles called after execution started \
             (circom_handles arena has freed slots)"
        );
        let cost: usize = handles.iter().map(circom_handle_cost).sum();
        self.circom_handles.data = handles;
        self.circom_handles.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }
}

/// Estimated heap cost of a [`CircomHandle`]: struct stack size +
/// the template name's allocated capacity + the args vec capacity.
fn circom_handle_cost(h: &CircomHandle) -> usize {
    std::mem::size_of::<CircomHandle>()
        + h.template_name.capacity()
        + h.template_args.capacity() * std::mem::size_of::<u64>()
}

#[cfg(test)]
mod circom_handle_tests {
    use super::*;

    fn sample_handle(id: u32, name: &str) -> CircomHandle {
        CircomHandle {
            library_id: id,
            template_name: name.to_string(),
            template_args: vec![2, 4],
        }
    }

    #[test]
    fn alloc_and_get_roundtrips() {
        let mut heap = Heap::new();
        let idx = heap
            .alloc_circom_handle(sample_handle(3, "Poseidon"))
            .expect("alloc should succeed");
        let got = heap.get_circom_handle(idx).expect("should be present");
        assert_eq!(got.library_id, 3);
        assert_eq!(got.template_name, "Poseidon");
        assert_eq!(got.template_args, vec![2, 4]);
    }

    #[test]
    fn alloc_charges_bytes_against_heap_budget() {
        let mut heap = Heap::new();
        let before = heap.bytes_allocated;
        heap.alloc_circom_handle(sample_handle(0, "Sigma")).unwrap();
        assert!(heap.bytes_allocated > before, "bytes_allocated should grow");
    }

    #[test]
    fn import_bulk_replaces_arena_contents() {
        let mut heap = Heap::new();
        heap.import_circom_handles(vec![
            sample_handle(0, "Square"),
            sample_handle(1, "Num2Bits"),
            sample_handle(2, "Poseidon"),
        ]);
        assert_eq!(heap.get_circom_handle(0).unwrap().template_name, "Square");
        assert_eq!(heap.get_circom_handle(1).unwrap().template_name, "Num2Bits");
        assert_eq!(heap.get_circom_handle(2).unwrap().template_name, "Poseidon");
    }

    #[test]
    fn gc_trace_marks_circom_handle_as_leaf() {
        // Allocate a handle, keep only a Value reference to it, run
        // trace against that root, and verify the arena slot was
        // marked (not freed on sweep).
        let mut heap = Heap::new();
        let idx = heap.alloc_circom_handle(sample_handle(7, "Sigma")).unwrap();
        let root = Value::circom_handle(idx);

        heap.trace(vec![root]);
        assert!(heap.circom_handles.is_marked(idx));
        heap.sweep();
        // After sweep the slot must still contain the original data
        // (marked → survived), not the reset placeholder.
        let survived = heap.get_circom_handle(idx).expect("should survive");
        assert_eq!(survived.template_name, "Sigma");
    }

    #[test]
    fn gc_sweep_collects_unmarked_circom_handle() {
        let mut heap = Heap::new();
        let idx = heap
            .alloc_circom_handle(sample_handle(9, "Discarded"))
            .unwrap();
        // Do NOT mark via trace — just sweep. The slot should be
        // marked as free and `get_circom_handle` returns None.
        heap.trace(vec![]);
        heap.sweep();
        assert!(heap.circom_handles.is_free(idx));
        assert!(heap.get_circom_handle(idx).is_none());
    }

    #[test]
    fn recount_live_bytes_includes_circom_handles() {
        let mut heap = Heap::new();
        heap.alloc_circom_handle(sample_handle(0, "Poseidon"))
            .unwrap();
        let total = heap.recount_live_bytes();
        assert!(total > 0);
    }
}
