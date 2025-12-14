use memory::{Heap, Value};
use std::collections::HashMap;

pub struct CallFrame {
    pub closure: u32, // Índice de la función en ejecución (en heap.functions)
    pub ip: usize,    // Instruction Pointer (índice en el bytecode)
    pub base: usize,  // Índice base en el `stack` donde empieza el registro 0 (R0)
}

pub struct VM {
    // Memoria
    pub heap: Heap,
    
    // Pila de Valores (Stack)
    // Un único vector gigante. Los registros son ventanas (slices) en este vector.
    pub stack: Vec<Value>, 
    
    // Pila de Llamadas (Call Stack)
    pub frames: Vec<CallFrame>,
    
    // Estado de variables globales
    pub globals: Vec<Value>,
    
    // Manejo de cadenas internadas (para evitar duplicados)
    pub interner: HashMap<String, u32>,
}

impl VM {
    pub fn new() -> Self {
        Self {
            heap: Heap::new(),
            stack: Vec::with_capacity(2048), // Pre-allocate some stack space
            frames: Vec::with_capacity(64),
            globals: Vec::new(),
            interner: HashMap::new(),
        }
    }
    
    pub fn interpret(&mut self) -> Result<(), String> {
        // Main loop stub
        // while let Some(frame) = self.frames.last_mut() { ... }
        Ok(())
    }
}
