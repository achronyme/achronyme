use crate::Value;
use std::collections::HashMap;
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

pub struct Heap {
    // Arenas tipadas: Vectores contiguos de datos reales
    pub strings: Vec<String>,
    pub lists: Vec<Vec<Value>>,
    pub maps: Vec<HashMap<String, Value>>, 
    pub functions: Vec<Function>,
    pub tensors: Vec<RealTensor>,
    pub complexes: Vec<Complex64>,
    
    // Gestión de memoria
    pub bytes_allocated: usize,
    pub next_gc: usize,
}

impl Heap {
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            lists: Vec::new(),
            maps: Vec::new(),
            functions: Vec::new(),
            tensors: Vec::new(),
            complexes: Vec::new(),
            bytes_allocated: 0,
            next_gc: 1024 * 1024,
        }
    }

    pub fn alloc_string(&mut self, s: String) -> u32 {
        let index = self.strings.len() as u32;
        self.bytes_allocated += s.capacity();
        self.strings.push(s);
        index
    }

    pub fn alloc_list(&mut self, l: Vec<Value>) -> u32 {
        let index = self.lists.len() as u32;
        self.bytes_allocated += l.capacity() * std::mem::size_of::<Value>();
        self.lists.push(l);
        index
    }
    
    pub fn collect_garbage(&mut self) {
        println!("GC: Running collection...");
    }

    pub fn get_string(&self, index: u32) -> Option<&String> {
        self.strings.get(index as usize)
    }

    pub fn get_list(&self, index: u32) -> Option<&Vec<Value>> {
        self.lists.get(index as usize)
    }

    pub fn get_list_mut(&mut self, index: u32) -> Option<&mut Vec<Value>> {
        self.lists.get_mut(index as usize)
    }

    pub fn alloc_function(&mut self, f: Function) -> u32 {
        let index = self.functions.len() as u32;
        self.bytes_allocated += f.chunk.len() * 4 + f.constants.len() * std::mem::size_of::<Value>();
        self.functions.push(f);
        index
    }

    pub fn get_function(&self, index: u32) -> Option<&Function> {
        self.functions.get(index as usize)
    }

    pub fn alloc_complex(&mut self, c: Complex64) -> u32 {
        let index = self.complexes.len() as u32;
        self.bytes_allocated += std::mem::size_of::<Complex64>();
        self.complexes.push(c);
        index
    }

    pub fn get_complex(&self, index: u32) -> Option<Complex64> {
        self.complexes.get(index as usize).copied()
    }

    pub fn import_strings(&mut self, strings: Vec<String>) {
        self.strings = strings;
    }
}
