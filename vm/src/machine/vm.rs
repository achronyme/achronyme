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
    pub globals: HashMap<u32, GlobalEntry>,
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
            globals: HashMap::new(),
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

                // Constants & Moves
                LoadConst => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    let val = func.constants.get(bx).cloned().unwrap_or(Value::nil());
                    self.set_reg(base, a, val);
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
