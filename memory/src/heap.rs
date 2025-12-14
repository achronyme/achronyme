use crate::Value;
use std::collections::{HashMap, HashSet};
use num_complex::Complex64;

// Placeholder types for now
pub type RealTensor = (); 

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub arity: u8,
    pub chunk: Vec<u32>,
    pub constants: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct Arena<T> {
    pub data: Vec<T>,
    pub free_indices: Vec<u32>,
}

impl<T> Arena<T> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            free_indices: Vec::new(),
        }
    }
}

pub struct Heap {
    // Typed Arenas
    pub strings: Arena<String>,
    pub lists: Arena<Vec<Value>>,
    pub maps: Arena<HashMap<String, Value>>, 
    pub functions: Arena<Function>,
    pub tensors: Arena<RealTensor>,
    pub complexes: Arena<Complex64>,
    
    // Mark State (One set per arena type)
    pub marked_strings: HashSet<u32>, 
    pub marked_lists: HashSet<u32>,
    pub marked_maps: HashSet<u32>,
    pub marked_functions: HashSet<u32>,
    pub marked_tensors: HashSet<u32>,
    pub marked_complexes: HashSet<u32>,

    // GC Metrics
    pub bytes_allocated: usize,
    pub next_gc_threshold: usize,
}

impl Heap {
    pub fn new() -> Self {
        Self {
            strings: Arena::new(),
            lists: Arena::new(),
            maps: Arena::new(),
            functions: Arena::new(),
            tensors: Arena::new(),
            complexes: Arena::new(),
            
            marked_strings: HashSet::new(),
            marked_lists: HashSet::new(),
            marked_maps: HashSet::new(),
            marked_functions: HashSet::new(),
            marked_tensors: HashSet::new(),
            marked_complexes: HashSet::new(),

            bytes_allocated: 0,
            next_gc_threshold: 1024 * 1024, // Start at 1MB
        }
    }

    pub fn alloc_string(&mut self, s: String) -> u32 {
        self.bytes_allocated += s.capacity();
        if self.should_collect() {
            // Signal GC needed? For now we just check.
            // In a real VM, we might trigger it, but 'collect_garbage' usually needs VM roots.
            // We'll leave the trigger to the VM loop or return a status if needed.
        }
        
        if let Some(idx) = self.strings.free_indices.pop() {
            self.strings.data[idx as usize] = s;
            idx
        } else {
            let index = self.strings.data.len() as u32;
            self.strings.data.push(s);
            index
        }
    }

    pub fn alloc_list(&mut self, l: Vec<Value>) -> u32 {
        self.bytes_allocated += l.capacity() * std::mem::size_of::<Value>();
        if let Some(idx) = self.lists.free_indices.pop() {
            self.lists.data[idx as usize] = l;
            idx
        } else {
            let index = self.lists.data.len() as u32;
            self.lists.data.push(l);
            index
        }
    }
    
    // Tracing (Mark Phase) logic
    pub fn trace(&mut self, roots: Vec<Value>) {
        let mut worklist = roots;
        
        while let Some(val) = worklist.pop() {
            if !val.is_obj() { continue; }
            let handle = val.as_handle().unwrap();
            
            // Dispatch by tag to check marking status
            let should_process = match val.type_tag() {
                crate::value::TAG_STRING => {
                    if !self.marked_strings.contains(&handle) {
                        self.marked_strings.insert(handle);
                        true
                    } else { false }
                },
                crate::value::TAG_LIST => {
                    if !self.marked_lists.contains(&handle) {
                        self.marked_lists.insert(handle);
                        true
                    } else { false }
                },
                crate::value::TAG_FUNCTION => {
                    if !self.marked_functions.contains(&handle) {
                        self.marked_functions.insert(handle);
                        true
                    } else { false }
                },
                crate::value::TAG_COMPLEX => {
                    if !self.marked_complexes.contains(&handle) {
                        self.marked_complexes.insert(handle);
                        // Complex has no children to trace
                        false
                    } else { false }
                },
                crate::value::TAG_MAP => {
                    if !self.marked_maps.contains(&handle) {
                        self.marked_maps.insert(handle);
                        true
                    } else { false }
                },
                crate::value::TAG_TENSOR => {
                    if !self.marked_tensors.contains(&handle) {
                        self.marked_tensors.insert(handle);
                        false // Assumed no children for now
                    } else { false }
                },
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
                    },
                    crate::value::TAG_FUNCTION => {
                         if let Some(f) = self.functions.data.get(handle as usize) {
                             worklist.extend(f.constants.clone());
                         }
                    },
                    crate::value::TAG_MAP => {
                        // For Map, we need to trace values. Keys are strings (implied marked if we trace keys?)
                        // If keys are interned strings managed by heap, we must mark them too!
                        if let Some(m) = self.maps.data.get(handle as usize) {
                            for (k, v) in m.iter() {
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
                    _ => {}
                }
            }
        }
    }

    
    pub fn sweep(&mut self) {
        // Strings
        for i in 0..self.strings.data.len() {
            let idx = i as u32;
            if !self.marked_strings.contains(&idx) && !self.strings.free_indices.contains(&idx) {
               self.strings.free_indices.push(idx);
               self.strings.data[i] = String::new(); // Free memory
            }
        }
        self.marked_strings.clear();

        // Lists
        for i in 0..self.lists.data.len() {
            let idx = i as u32;
             if !self.marked_lists.contains(&idx) && !self.lists.free_indices.contains(&idx) {
               self.lists.free_indices.push(idx);
               self.lists.data[i] = Vec::new(); // Free memory
            }
        }
        self.marked_lists.clear();
        
        // Functions
         for i in 0..self.functions.data.len() {
            let idx = i as u32;
             if !self.marked_functions.contains(&idx) && !self.functions.free_indices.contains(&idx) {
               self.functions.free_indices.push(idx);
               // We replace with dummy
               self.functions.data[i] = Function { name: String::new(), arity: 0, chunk: vec![], constants: vec![] };
            }
        }
        self.marked_functions.clear();
        
         // Complexes
         for i in 0..self.complexes.data.len() {
            let idx = i as u32;
             if !self.marked_complexes.contains(&idx) && !self.complexes.free_indices.contains(&idx) {
               self.complexes.free_indices.push(idx);
               // Complex is Copy, just leave it or zero it?
               // It doesn't hold heap memory itself, so just marking as free is enough for reuse.
               // Overwriting with default might help debugging.
               self.complexes.data[i] = Complex64::default();
            }
        }
        self.marked_complexes.clear();
        
        // Reset GC threshold just in case
        self.bytes_allocated = 0; // Approximate reset or sophisticated recalculation
    }

    pub fn should_collect(&self) -> bool {
        self.bytes_allocated > self.next_gc_threshold
    }

    pub fn get_string(&self, index: u32) -> Option<&String> {
        // Only return if not freed? Or assume VM handle safety?
        // Typically strict check: if free_indices.contains(index) return None.
        // For speed, we trust the handle unless debugging.
        self.strings.data.get(index as usize)
    }

    pub fn get_list(&self, index: u32) -> Option<&Vec<Value>> {
        self.lists.data.get(index as usize)
    }

    pub fn get_list_mut(&mut self, index: u32) -> Option<&mut Vec<Value>> {
        self.lists.data.get_mut(index as usize)
    }

    pub fn alloc_function(&mut self, f: Function) -> u32 {
        self.bytes_allocated += f.chunk.len() * 4 + f.constants.len() * std::mem::size_of::<Value>();
        if let Some(idx) = self.functions.free_indices.pop() {
            self.functions.data[idx as usize] = f;
            idx
        } else {
            let index = self.functions.data.len() as u32;
            self.functions.data.push(f);
            index
        }
    }

    pub fn get_function(&self, index: u32) -> Option<&Function> {
        self.functions.data.get(index as usize)
    }

    pub fn alloc_complex(&mut self, c: Complex64) -> u32 {
        self.bytes_allocated += std::mem::size_of::<Complex64>();
        if let Some(idx) = self.complexes.free_indices.pop() {
            self.complexes.data[idx as usize] = c;
            idx
        } else {
            let index = self.complexes.data.len() as u32;
            self.complexes.data.push(c);
            index
        }
    }

    pub fn get_complex(&self, index: u32) -> Option<Complex64> {
        self.complexes.data.get(index as usize).copied()
    }

    pub fn import_strings(&mut self, strings: Vec<String>) {
        self.strings.data = strings;
        self.strings.free_indices.clear();
    }
}
