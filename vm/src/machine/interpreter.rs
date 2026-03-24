use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::arithmetic::ArithmeticOps;
use super::closure::ClosureOps;
use super::comparison::ComparisonOps;
use super::control::ControlFlowOps;
use super::data::DataOps;
use super::gc::GarbageCollector;
use super::globals::GlobalOps;
use super::iterator::IteratorOps;
use super::stack::StackOps;
use super::value_ops::ValueOps;
use super::vm::STACK_MAX;

/// Trait for the main interpretation loop
pub trait InterpreterOps {
    fn interpret_inner(&mut self) -> Result<(), RuntimeError>;
}

impl InterpreterOps for super::vm::VM {
    fn interpret_inner(&mut self) -> Result<(), RuntimeError> {
        // Validation: Check initial frame fits
        if let Some(frame) = self.frames.last() {
            let closure = self
                .heap
                .get_closure(frame.closure)
                .ok_or(RuntimeError::FunctionNotFound)?;
            let func = self
                .heap
                .get_function(closure.function)
                .ok_or(RuntimeError::FunctionNotFound)?;
            if frame.base + (func.max_slots as usize) >= STACK_MAX {
                return Err(RuntimeError::StackOverflow);
            }
        }

        self.run_until_frame_depth(0)
    }
}

impl super::vm::VM {
    /// Run the interpreter loop until the frame stack drops to `target_depth`.
    ///
    /// This is the core execution engine. `interpret_inner()` delegates here
    /// with `target_depth = 0` (run until all frames are consumed).
    /// `call_value()` uses a higher target to execute a single closure call
    /// and return to the native caller.
    pub(crate) fn run_until_frame_depth(
        &mut self,
        target_depth: usize,
    ) -> Result<(), RuntimeError> {
        while self.frames.len() > target_depth {
            // GC Check Point
            if self.heap.request_gc || self.stress_mode {
                self.collect_garbage();
                self.heap.request_gc = false;
            }

            // Heap Limit Check Point
            if self.heap.heap_limit_exceeded {
                self.collect_garbage();
                self.heap.heap_limit_exceeded = false;
                if self.heap.bytes_allocated > self.heap.max_heap_bytes {
                    return Err(RuntimeError::HeapLimitExceeded {
                        limit: self.heap.max_heap_bytes,
                        allocated: self.heap.bytes_allocated,
                    });
                }
            }

            let frame_idx = self.frames.len() - 1;

            let (closure_idx, ip, base) = {
                let f = &self.frames[frame_idx];
                (f.closure, f.ip, f.base)
            };

            let func = {
                let closure = self
                    .heap
                    .get_closure(closure_idx)
                    .ok_or(RuntimeError::FunctionNotFound)?;
                self.heap
                    .get_function(closure.function)
                    .ok_or(RuntimeError::FunctionNotFound)?
            };

            if ip >= func.chunk.len() {
                self.frames.pop();
                continue;
            }

            let instruction = func.chunk[ip];
            let max_slots = func.max_slots as usize;
            let chunk_len = func.chunk.len();
            self.frames[frame_idx].ip += 1;

            // Instruction fuel check
            if let Some(ref mut budget) = self.instruction_budget {
                if *budget == 0 {
                    return Err(RuntimeError::InstructionBudgetExhausted);
                }
                *budget -= 1;
            }

            let op_byte = decode_opcode(instruction);
            let op = OpCode::from_u8(op_byte).ok_or(RuntimeError::InvalidOpcode(op_byte))?;

            use crate::opcode::OpCode::*;

            match op {
                // Arithmetic (delegated to arithmetic.rs)
                Add | Sub | Mul | Div | Mod | Pow | Neg => {
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
                    if dest > chunk_len {
                        return Err(RuntimeError::OutOfBounds(format!(
                            "Jump target {dest} exceeds chunk length {chunk_len}"
                        )));
                    }
                    self.frames[frame_idx].ip = dest;
                }

                JumpIfFalse => {
                    let a = decode_a(instruction) as usize;
                    let dest = decode_bx(instruction) as usize;
                    if dest > chunk_len {
                        return Err(RuntimeError::OutOfBounds(format!(
                            "JumpIfFalse target {dest} exceeds chunk length {chunk_len}"
                        )));
                    }
                    let val = self.get_reg(base, a)?;
                    if val.is_falsey() {
                        self.frames[frame_idx].ip = dest;
                    }
                }

                // Comparisons (delegated to comparison.rs)
                Eq | Lt | Gt | NotEq | Le | Ge | LogNot => {
                    self.handle_comparison(op, instruction, base)?;
                }

                // Constants & Moves
                LoadConst => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    let val = func.constants.get(bx).cloned().ok_or_else(|| {
                        RuntimeError::OutOfBounds(format!(
                            "constant index {bx} out of range (len {})",
                            func.constants.len()
                        ))
                    })?;
                    self.set_reg(base, a, val)?;
                }

                LoadTrue => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::true_val())?;
                }

                LoadFalse => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::false_val())?;
                }

                LoadNil => {
                    let a = decode_a(instruction) as usize;
                    self.set_reg(base, a, Value::nil())?;
                }

                Move => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let val = self.get_reg(base, b)?;
                    self.set_reg(base, a, val)?;
                }

                Print => {
                    let a = decode_a(instruction) as usize;
                    let val = self.get_reg(base, a)?;
                    println!("{}", self.val_to_string(&val));
                }

                Prove => {
                    self.handle_prove(instruction, base, closure_idx)?;
                }

                MethodCall => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;

                    // Method name is in R[base + b - 1] (LoadConst prior)
                    let name_val = self.get_reg(base, b.wrapping_sub(1))?;
                    let name_handle = name_val.as_handle().ok_or_else(|| {
                        RuntimeError::TypeMismatch(
                            "MethodCall: method name register is not a string".into(),
                        )
                    })?;
                    let method_name = self
                        .heap
                        .get_string(name_handle)
                        .ok_or(RuntimeError::StaleHeapHandle {
                            type_name: "String",
                            context: "MethodCall name",
                        })?
                        .clone();

                    // Receiver is in R[base + b]
                    let receiver = self.get_reg(base, b)?;
                    let tag = receiver.tag();

                    // Collect arguments from R[base+b+1..base+b+c]
                    let mut args = Vec::with_capacity(c);
                    for i in 1..=c {
                        args.push(self.get_reg(base, b + i)?);
                    }

                    // Lookup method in prototype registry
                    if let Some(method_fn) = self.prototype_registry.lookup(tag, &method_name) {
                        let result = method_fn(self, receiver, &args)?;
                        self.set_reg(base, a, result)?;
                    } else if receiver.is_map() {
                        // Fallback: map-as-object pattern — look up the key
                        // in the map and call it if it's a function/closure.
                        let map_handle = receiver
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad map handle".into()))?;
                        let callee = self
                            .heap
                            .get_map(map_handle)
                            .and_then(|m| m.get(&method_name).copied())
                            .ok_or_else(|| {
                                RuntimeError::TypeMismatch(format!(
                                    "Map has no method or key '{method_name}'"
                                ))
                            })?;
                        if !callee.is_closure() && !callee.is_native() {
                            return Err(RuntimeError::TypeMismatch(format!(
                                "Map key '{method_name}' is not callable"
                            )));
                        }
                        let result = self.call_value(callee, &args)?;
                        self.set_reg(base, a, result)?;
                    } else {
                        let type_name = match tag {
                            0 => "Int",
                            1 => "Nil",
                            2 | 3 => "Bool",
                            4 => "String",
                            5 => "List",
                            6 => "Map",
                            7 => "Function",
                            8 => "Field",
                            9 => "Proof",
                            10 => "Native",
                            11 => "Function",
                            12 => "Iterator",
                            13 => "BigInt",
                            _ => "Unknown",
                        };
                        return Err(RuntimeError::TypeMismatch(format!(
                            "{type_name} has no method '{method_name}'"
                        )));
                    }
                }

                BuildList | BuildMap | GetIndex | SetIndex => {
                    self.handle_data(op, instruction, base)?;
                }

                // Closures & Upvalues (delegated to closure.rs)
                OpCode::GetUpvalue | SetUpvalue | CloseUpvalue | Closure => {
                    self.handle_closure(op, instruction, base, frame_idx)?;
                }

                // Iterators (delegated to iterator.rs)
                OpCode::GetIter | OpCode::ForIter => {
                    self.handle_iterator(op, instruction, base, frame_idx, max_slots, chunk_len)?;
                }

                Nop => { /* no-op */ }
            }
        }
        Ok(())
    }
}
