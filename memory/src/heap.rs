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
    pub data: Vec<T>,
    pub free_indices: Vec<u32>,
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
    // Typed Arenas
    pub strings: Arena<String>,
    pub lists: Arena<Vec<Value>>,
    pub maps: Arena<HashMap<String, Value>>,
    pub functions: Arena<Function>,
    pub upvalues: Arena<Upvalue>,
    pub closures: Arena<Closure>,
    pub iterators: Arena<IteratorObj>,
    pub fields: Arena<FieldElement>,
    pub proofs: Arena<ProofObject>,

    // Mark State (One set per arena type)
    pub marked_strings: HashSet<u32>,
    pub marked_lists: HashSet<u32>,
    pub marked_maps: HashSet<u32>,
    pub marked_functions: HashSet<u32>,
    pub marked_upvalues: HashSet<u32>,
    pub marked_closures: HashSet<u32>,
    pub marked_iterators: HashSet<u32>,
    pub marked_fields: HashSet<u32>,
    pub marked_proofs: HashSet<u32>,

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
                        // For Map, we need to trace values. Keys are strings (implied marked if we trace keys?)
                        // If keys are interned strings managed by heap, we must mark them too!
                        if let Some(m) = self.maps.data.get(handle as usize) {
                            for (_k, v) in m.iter() {
                                worklist.push(v.clone());
                                // We might need to mark the string key if it's dynamic?
                                // Currently keys are String in HashMap<String, Value>.
                                // But Strings in Rust heap are not our Heap handles unless we intern them?
                                // Our Heap.strings is Arena<String>.
                                // If the Map stores raw String keys, they are native Rust heap, managed by HashMap.
                                // We don't need to trace strict handles for them unless we store handles.
                                // Definition: pub maps: Arena<HashMap<String, Value>>.
                                // So keys are owned by HashMap. Values are traced. OK.
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

        // Adjust global counter safely
        self.bytes_allocated = self.bytes_allocated.saturating_sub(freed_bytes);

        // Dynamic Threshold Adjustment:
        // After sweep, we set new threshold to X * current_heap to avoid thrashing.
        // E.g. grow threshold to 2x current size.
        self.next_gc_threshold = self.bytes_allocated * 2;
        if self.next_gc_threshold < 1024 * 1024 {
            self.next_gc_threshold = 1024 * 1024; // Min 1MB
        }
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
