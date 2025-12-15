use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::native::NativeObj;
use crate::opcode::{instruction::*, OpCode};
use memory::{Heap, Value};
use std::collections::HashMap;

use super::arithmetic::ArithmeticOps;
use super::control::ControlFlowOps;
use super::frame::CallFrame;
use super::gc::GarbageCollector;
use super::globals::GlobalOps;
use super::native::NativeRegistry;
use super::stack::StackOps;

/// The Virtual Machine struct
pub struct VM {
    pub heap: Heap,
    pub stack: Vec<Value>,
    pub frames: Vec<CallFrame>,
    pub globals: Vec<GlobalEntry>,
    pub interner: HashMap<String, u32>,
    pub natives: Vec<NativeObj>,
    
    /// Function prototypes (handles) for O(1) CLOSURE lookup
    pub prototypes: Vec<u32>,
    
    // Passive Debug Symbols (Sidecar)
    pub debug_symbols: Option<HashMap<u16, String>>,
}

pub const STACK_MAX: usize = 65_536;

impl VM {
    /// Create a new VM instance with bootstrapped native functions
    pub fn new() -> Self {
        // Pre-allocate fixed-size stack
        let stack = vec![Value::nil(); STACK_MAX];
        
        let mut vm = Self {
            heap: Heap::new(),
            stack,
            frames: Vec::with_capacity(64),
            globals: Vec::with_capacity(64),
            interner: HashMap::new(),
            natives: Vec::new(),
            prototypes: Vec::new(),
            debug_symbols: None,
        };

        // Bootstrap native functions
        vm.bootstrap_natives();

        vm
    }

    /// Helper to format values for display (Clean UX)
    pub fn val_to_string(&self, val: &Value) -> String {
        match val {
            v if v.is_string() => {
                let handle = v.as_handle().unwrap();
                self.heap.get_string(handle).cloned().unwrap_or("<bad string>".into())
            },
            v if v.is_number() => format!("{}", v.as_number().unwrap()),
            v if v.is_bool() => format!("{}", v.as_bool().unwrap()),
            v if v.is_nil() => "nil".to_string(),
            v if v.is_list() => format!("[List:{}]", v.as_handle().unwrap()), // Basic placeholder
            v if v.is_map() => format!("{{Map:{}}}", v.as_handle().unwrap()),   // Basic placeholder
            _ => format!("{:?}", val), // Fallback
        }
    }

    /// Main interpretation loop
    pub fn interpret(&mut self) -> Result<(), RuntimeError> {
        // Validation: Check checking initial frame fits
        if let Some(frame) = self.frames.last() {
            let func = self.heap.get_function(frame.closure)
                .ok_or(RuntimeError::FunctionNotFound)?;
             if frame.base + (func.max_slots as usize) >= STACK_MAX {
                 return Err(RuntimeError::StackOverflow);
             }
        }

        while !self.frames.is_empty() {
            // GC Check
            if self.heap.should_collect() {
                self.collect_garbage();
            }

            let frame_idx = self.frames.len() - 1;

            let (closure_idx, ip, base) = {
                let f = &self.frames[frame_idx];
                (f.closure, f.ip, f.base)
            };

            let func = self
                .heap
                .get_function(closure_idx)
                .ok_or(RuntimeError::FunctionNotFound)?;

            if ip >= func.chunk.len() {
                self.frames.pop();
                continue;
            }

            let instruction = func.chunk[ip];
            self.frames[frame_idx].ip += 1;

            let op_byte = decode_opcode(instruction);
            let op = OpCode::from_u8(op_byte).ok_or(RuntimeError::InvalidOpcode(op_byte))?;

            // Inline dispatch to avoid borrow conflicts
            use crate::opcode::OpCode::*;

            match op {
                // Arithmetic (delegated to arithmetic.rs)
                Add | Sub | Mul | Div | Pow | Neg | Sqrt | NewComplex => {
                    self.handle_arithmetic(op, instruction, base)?;
                }

                // Control Flow (delegated to control.rs)
                Call | Return => {
                    self.handle_control(op, instruction, base)?;
                }

                // Globals (delegated to globals.rs)
                DefGlobalVar | DefGlobalLet | GetGlobal | SetGlobal => {
                    self.handle_globals(op, instruction, base, closure_idx)?;
                }

                // Control Flow - Jumps
                Jump => {
                    let dest = decode_bx(instruction) as usize;
                    self.frames[frame_idx].ip = dest;
                }

                JumpIfFalse => {
                    let a = decode_a(instruction) as usize;
                    let dest = decode_bx(instruction) as usize;
                    let val = self.get_reg(base, a);
                    if val.is_falsey() {
                        self.frames[frame_idx].ip = dest;
                    }
                }

                Eq => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b);
                    let v2 = self.get_reg(base, c);
                    self.set_reg(base, a, Value::bool(v1 == v2));
                }

                Lt => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b);
                    let v2 = self.get_reg(base, c);
                    
                    if let (Some(n1), Some(n2)) = (v1.as_number(), v2.as_number()) {
                        self.set_reg(base, a, Value::bool(n1 < n2));
                    } else {
                        return Err(RuntimeError::TypeMismatch("Expected numbers for < comparison".to_string()));
                    }
                }

                Gt => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b);
                    let v2 = self.get_reg(base, c);

                    if let (Some(n1), Some(n2)) = (v1.as_number(), v2.as_number()) {
                        self.set_reg(base, a, Value::bool(n1 > n2));
                    } else {
                        return Err(RuntimeError::TypeMismatch("Expected numbers for > comparison".to_string()));
                    }
                }

                // Constants & Moves
                LoadConst => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    let val = func.constants.get(bx).cloned().unwrap_or(Value::nil());
                    self.set_reg(base, a, val);
                }

                LoadTrue => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::true_val());
                }

                LoadFalse => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::false_val());
                }

                LoadNil => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::nil());
                }

                Move => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let val = self.get_reg(base, b);
                    self.set_reg(base, a, val);
                }

                Print => {
                    let a = decode_a(instruction) as usize;
                    let val = self.get_reg(base, a);
                    // Simple debug print for now
                    println!("{:?}", val);
                }

                Closure => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    
                    // O(1) direct lookup into prototypes table
                    let func_val = if bx < self.prototypes.len() {
                        Value::function(self.prototypes[bx])
                    } else {
                        Value::nil() // Error: invalid prototype index
                    };
                    self.set_reg(base, a, func_val);
                }

                _ => {
                    return Err(RuntimeError::Unknown(format!(
                        "Unimplemented opcode {:?}",
                        op
                    )))
                }
            }
        }
        Ok(())
    }

    /// Sidecar Loader: Parses debug symbols from raw bytes
    pub fn load_debug_section(&mut self, bytes: &[u8]) {
        if bytes.len() < 4 {
            return; // Not enough bytes for Header + Count
        }

        let mut cursor = 0;

        // 1. Check Magic (0xDB 0x67)
        if bytes[cursor] != 0xDB || bytes[cursor + 1] != 0x67 {
            return; // Invalid or missing section
        }
        cursor += 2;

        // 2. Read Count
        let count = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;

        let mut map = HashMap::new();

        for _ in 0..count {
            if cursor + 4 > bytes.len() {
                break; // Truncated
            }

            // Global Index
            let global_idx = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
            cursor += 2;

            // Name Length
            let name_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;

            if cursor + name_len > bytes.len() {
                break; // Truncated name
            }

            // Name Bytes
            let name_bytes = &bytes[cursor..cursor + name_len];
            cursor += name_len;

            if let Ok(name) = std::str::from_utf8(name_bytes) {
                map.insert(global_idx, name.to_string());
            }
        }

        self.debug_symbols = Some(map);
    }
}
