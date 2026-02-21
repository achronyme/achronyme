use crate::Value;
use crate::field::FieldElement;
use std::collections::{HashMap, HashSet};

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

    // Mark State — pub(crate) to prevent external mark manipulation
    pub(crate) marked_strings: HashSet<u32>,
    pub(crate) marked_lists: HashSet<u32>,
    pub(crate) marked_maps: HashSet<u32>,
    pub(crate) marked_functions: HashSet<u32>,
    pub(crate) marked_upvalues: HashSet<u32>,
    pub(crate) marked_closures: HashSet<u32>,
    pub(crate) marked_iterators: HashSet<u32>,
    pub(crate) marked_fields: HashSet<u32>,
    pub(crate) marked_proofs: HashSet<u32>,

    // GC Metrics
    pub bytes_allocated: usize,
    pub next_gc_threshold: usize,
    pub request_gc: bool,
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

            marked_strings: HashSet::new(),
            marked_lists: HashSet::new(),
            marked_maps: HashSet::new(),
            marked_functions: HashSet::new(),
            marked_upvalues: HashSet::new(),
            marked_closures: HashSet::new(),
            marked_iterators: HashSet::new(),
            marked_fields: HashSet::new(),
            marked_proofs: HashSet::new(),

            bytes_allocated: 0,
            next_gc_threshold: 1024 * 1024, // Start at 1MB
            request_gc: false,
        }
    }

    pub fn check_gc(&mut self) {
        if self.bytes_allocated > self.next_gc_threshold {
            self.request_gc = true;
        }
    }

    /// Mark an upvalue index as reachable (for open upvalue rooting in GC).
    pub fn mark_upvalue(&mut self, idx: u32) {
        self.marked_upvalues.insert(idx);
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
        self.marked_lists.contains(&idx)
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
        let capacity = m.capacity();
        let entry_size = std::mem::size_of::<String>()
            + std::mem::size_of::<Value>()
            + std::mem::size_of::<u64>();
        self.bytes_allocated += capacity * entry_size;
        self.check_gc();
        self.maps.alloc(m)
    }

    pub fn get_map(&self, index: u32) -> Option<&HashMap<String, Value>> {
        self.maps.get(index)
    }

    pub fn get_map_mut(&mut self, index: u32) -> Option<&mut HashMap<String, Value>> {
        self.maps.get_mut(index)
    }

    // Tracing (Mark Phase) logic
    pub fn trace(&mut self, roots: Vec<Value>) {
        let mut worklist = roots;

        while let Some(val) = worklist.pop() {
            if !val.is_obj() {
                continue;
            }
            let handle = val.as_handle().unwrap();

            // Dispatch by tag to check marking status
            let should_process = match val.type_tag() {
                crate::value::TAG_STRING => {
                    if !self.marked_strings.contains(&handle) {
                        self.marked_strings.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_LIST => {
                    if !self.marked_lists.contains(&handle) {
                        self.marked_lists.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_FUNCTION => {
                    if !self.marked_functions.contains(&handle) {
                        self.marked_functions.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_CLOSURE => {
                    if !self.marked_closures.contains(&handle) {
                        self.marked_closures.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_MAP => {
                    if !self.marked_maps.contains(&handle) {
                        self.marked_maps.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_ITER => {
                    if !self.marked_iterators.contains(&handle) {
                        self.marked_iterators.insert(handle);
                        true
                    } else {
                        false
                    }
                }
                crate::value::TAG_FIELD => {
                    // Leaf type: no children to trace
                    self.marked_fields.insert(handle);
                    false
                }
                crate::value::TAG_PROOF => {
                    // Leaf type: no children to trace
                    self.marked_proofs.insert(handle);
                    false
                }
                _ => false,
            };

            if should_process {
                // If we jus marked it, we need to add its children to worklist.
                // We clone the children containers (List/Function constants) to avoid &mut self conflicts.
                // Value is Copy (u64), so Vec<Value> clone is efficient (memcpy).
                match val.type_tag() {
                    crate::value::TAG_LIST => {
                        if let Some(l) = self.lists.data.get(handle as usize) {
                            worklist.extend(l.clone());
                        }
                    }
                    crate::value::TAG_FUNCTION => {
                        if let Some(f) = self.functions.data.get(handle as usize) {
                            worklist.extend(f.constants.clone());
                        }
                    }
                    crate::value::TAG_CLOSURE => {
                        if let Some(c) = self.closures.data.get(handle as usize) {
                            // 1. Mark Function
                            worklist.push(Value::function(c.function));
                            // 2. Mark Upvalues
                            for &up_idx in &c.upvalues {
                                if !self.marked_upvalues.contains(&up_idx) {
                                    self.marked_upvalues.insert(up_idx);
                                    // Trace value inside upvalue (if closed, it matters)
                                    // If open, it's stack or Nil, safe to trace
                                    if let Some(u) = self.upvalues.data.get(up_idx as usize) {
                                        if let UpvalueLocation::Closed(val) = u.location {
                                            worklist.push(val);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    crate::value::TAG_MAP => {
                        // Keys are Rust-owned Strings inside HashMap<String, Value>,
                        // NOT arena handles — they are freed when the HashMap drops.
                        // Only values need GC tracing.
                        if let Some(m) = self.maps.data.get(handle as usize) {
                            for v in m.values() {
                                worklist.push(*v);
                            }
                        }
                    }
                    crate::value::TAG_ITER => {
                        if let Some(iter) = self.iterators.data.get(handle as usize) {
                            worklist.push(iter.source);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub fn sweep(&mut self) {
        let mut freed_bytes = 0;

        // Strings
        for i in 0..self.strings.data.len() {
            let idx = i as u32;
            if !self.marked_strings.contains(&idx) && !self.strings.is_free(idx) {
                self.strings.mark_free(idx);
                freed_bytes += self.strings.data[i].capacity();
                self.strings.data[i] = String::new(); // Free memory
            }
        }
        self.marked_strings.clear();

        // Lists
        for i in 0..self.lists.data.len() {
            let idx = i as u32;
            if !self.marked_lists.contains(&idx) && !self.lists.is_free(idx) {
                self.lists.mark_free(idx);
                freed_bytes += self.lists.data[i].capacity() * std::mem::size_of::<Value>();
                self.lists.data[i] = Vec::new(); // Free memory
            }
        }
        self.marked_lists.clear();

        // Functions
        for i in 0..self.functions.data.len() {
            let idx = i as u32;
            if !self.marked_functions.contains(&idx) && !self.functions.is_free(idx)
            {
                self.functions.mark_free(idx);
                let f = &self.functions.data[i];
                freed_bytes += f.chunk.capacity() * 4;
                freed_bytes += f.constants.capacity() * std::mem::size_of::<Value>();

                // We replace with dummy
                self.functions.data[i] = Function {
                    name: String::new(),
                    arity: 0,
                    max_slots: 0,
                    chunk: vec![],
                    constants: vec![],
                    upvalue_info: vec![],
                };
            }
        }
        self.marked_functions.clear();

        // Closures
        for i in 0..self.closures.data.len() {
            let idx = i as u32;
            if !self.marked_closures.contains(&idx) && !self.closures.is_free(idx) {
                self.closures.mark_free(idx);
                let c = &self.closures.data[i];
                freed_bytes += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;

                self.closures.data[i] = Closure {
                    function: 0,
                    upvalues: vec![],
                };
            }
        }
        self.marked_closures.clear();

        // Upvalues
        for i in 0..self.upvalues.data.len() {
            let idx = i as u32;
            if !self.marked_upvalues.contains(&idx) && !self.upvalues.is_free(idx) {
                self.upvalues.mark_free(idx);
                freed_bytes += std::mem::size_of::<Upvalue>();

                self.upvalues.data[i] = Upvalue {
                    location: UpvalueLocation::Closed(Value::nil()),
                    next_open: None,
                };
            }
        }
        self.marked_upvalues.clear();

        // Iterators
        for i in 0..self.iterators.data.len() {
            let idx = i as u32;
            if !self.marked_iterators.contains(&idx) && !self.iterators.is_free(idx)
            {
                self.iterators.mark_free(idx);
                freed_bytes += std::mem::size_of::<IteratorObj>();
                // Reset iterator (Value::nil() source)
                self.iterators.data[i] = IteratorObj {
                    source: Value::nil(),
                    index: 0,
                };
            }
        }
        self.marked_iterators.clear();

        // Fields (leaf type, 32 bytes each)
        for i in 0..self.fields.data.len() {
            let idx = i as u32;
            if !self.marked_fields.contains(&idx) && !self.fields.is_free(idx) {
                self.fields.mark_free(idx);
                freed_bytes += std::mem::size_of::<FieldElement>();
                self.fields.data[i] = FieldElement::ZERO;
            }
        }
        self.marked_fields.clear();

        // Proofs
        for i in 0..self.proofs.data.len() {
            let idx = i as u32;
            if !self.marked_proofs.contains(&idx) && !self.proofs.is_free(idx) {
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
        self.marked_proofs.clear();

        // Recompute bytes_allocated from surviving objects (self-correcting).
        // This eliminates drift from untracked mutations (push, insert, etc.)
        // at negligible cost — the sweep loop already touched every slot.
        self.bytes_allocated = self.recount_live_bytes();

        // Dynamic Threshold Adjustment:
        // After sweep, we set new threshold to X * current_heap to avoid thrashing.
        // E.g. grow threshold to 2x current size.
        self.next_gc_threshold = self.bytes_allocated * 2;
        if self.next_gc_threshold < 1024 * 1024 {
            self.next_gc_threshold = 1024 * 1024; // Min 1MB
        }
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
        for (i, m) in self.maps.data.iter().enumerate() {
            if !self.maps.is_free(i as u32) {
                let capacity = m.capacity();
                let entry_size = std::mem::size_of::<String>() + std::mem::size_of::<Value>();
                total += capacity * entry_size;
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

    pub fn import_strings(&mut self, strings: Vec<String>) {
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
}
