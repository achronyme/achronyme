pub mod opcode;
pub use opcode::OpCode;

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
        // Basic dispatcher loop
        // We assume valid frames are pushed before calling interpret usually.
        // Or interpret takes a "root" function.
        
        // For testing, caller pushes a frame.
        
        while !self.frames.is_empty() {
             // Peek frame to get ip and code
             let frame_idx = self.frames.len() - 1;
             
             // We need to access heap to get code.
             // Borrow checker struggle: self.frames (mut), self.heap (ref), self.stack (mut).
             // We can extract what we need from frame index
             let (closure_idx, ip, base) = {
                 let f = &self.frames[frame_idx];
                 (f.closure, f.ip, f.base)
             };
             
             let func = self.heap.get_function(closure_idx)
                 .ok_or_else(|| "Function not found".to_string())?;
             
             if ip >= func.chunk.len() {
                 self.frames.pop();
                 continue; // Return from void or finished
             }
             
             let instruction = func.chunk[ip];
             // Increment IP in frame immediately or after?
             self.frames[frame_idx].ip += 1;
             
             // Decode
             use opcode::instruction::*;
             use opcode::OpCode;
             
             let op_byte = decode_opcode(instruction);
             let op = OpCode::from_u8(op_byte).ok_or_else(|| format!("Invalid opcode {}", op_byte))?;
             
             match op {
                 OpCode::LoadConst => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     let val = func.constants.get(bx).cloned().unwrap_or(Value::Nil);
                     // R[A] = val
                     self.set_reg(base, a, val);
                 },
                 
                 OpCode::Add => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     
                     let res = match (vb, vc) {
                         (Value::Number(n1), Value::Number(n2)) => Value::Number(n1 + n2),
                         _ => return Err("Type error in Add".into()),
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Mul => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     
                     let res = match (vb, vc) {
                         (Value::Number(n1), Value::Number(n2)) => Value::Number(n1 * n2),
                         _ => return Err("Type error in Mul".into()),
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Return => {
                     // R[A] is return value
                     let a = decode_a(instruction) as usize;
                     let _ret_val = self.get_reg(base, a);
                     // For now just pop frame. Ret val handling needs caller convention.
                     self.frames.pop();
                 },
                 
                 _ => return Err(format!("Unimplemented opcode {:?}", op)),
             }
        }
        Ok(())
    }
    
    // Helper to safely access registers in the giant stack
    fn get_reg(&self, base: usize, reg: usize) -> Value {
        self.stack.get(base + reg).cloned().unwrap_or(Value::Nil)
    }
    
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) {
        let idx = base + reg;
        if idx >= self.stack.len() {
            self.stack.resize(idx + 1, Value::Nil);
        }
        self.stack[idx] = val;
    }
}
