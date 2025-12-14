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
}

impl VM {
    /// Create a new VM instance with bootstrapped native functions
    pub fn new() -> Self {
        let mut vm = Self {
            heap: Heap::new(),
            stack: Vec::with_capacity(2048),
            frames: Vec::with_capacity(64),
            globals: Vec::with_capacity(64),
            interner: HashMap::new(),
            natives: Vec::new(),
        };

        // Bootstrap native functions
        vm.bootstrap_natives();

        vm
    }

    /// Main interpretation loop
    pub fn interpret(&mut self) -> Result<(), RuntimeError> {
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
}
