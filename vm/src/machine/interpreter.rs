use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::arithmetic::ArithmeticOps;
use super::control::ControlFlowOps;
use super::data::DataOps;
use super::gc::GarbageCollector;
use super::globals::GlobalOps;
use super::stack::StackOps;
use super::upvalue::UpvalueOps;
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

                Eq => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;
                    self.set_reg(base, a, Value::bool(self.values_equal(v1, v2)))?;
                }

                Lt => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;

                    if let (Some(n1), Some(n2)) = (v1.as_int(), v2.as_int()) {
                        self.set_reg(base, a, Value::bool(n1 < n2))?;
                    } else if v1.is_field() && v2.is_field() {
                        let h1 = v1
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let h2 = v2
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let f1 = self
                            .heap
                            .get_field(h1)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        let f2 = self
                            .heap
                            .get_field(h2)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        self.set_reg(base, a, Value::bool(f1.to_canonical() < f2.to_canonical()))?;
                    } else if v1.is_bigint() && v2.is_bigint() {
                        let (h1, h2) = (
                            v1.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                            v2.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                        );
                        let b1 = self
                            .heap
                            .get_bigint(h1)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        let b2 = self
                            .heap
                            .get_bigint(h2)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        self.set_reg(base, a, Value::bool(b1 < b2))?;
                    } else {
                        return Err(RuntimeError::TypeMismatch(
                            "Expected numeric values for < comparison".to_string(),
                        ));
                    }
                }

                Gt => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;

                    if let (Some(n1), Some(n2)) = (v1.as_int(), v2.as_int()) {
                        self.set_reg(base, a, Value::bool(n1 > n2))?;
                    } else if v1.is_field() && v2.is_field() {
                        let h1 = v1
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let h2 = v2
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let f1 = self
                            .heap
                            .get_field(h1)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        let f2 = self
                            .heap
                            .get_field(h2)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        self.set_reg(base, a, Value::bool(f1.to_canonical() > f2.to_canonical()))?;
                    } else if v1.is_bigint() && v2.is_bigint() {
                        let (h1, h2) = (
                            v1.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                            v2.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                        );
                        let b1 = self
                            .heap
                            .get_bigint(h1)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        let b2 = self
                            .heap
                            .get_bigint(h2)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        self.set_reg(base, a, Value::bool(b1 > b2))?;
                    } else {
                        return Err(RuntimeError::TypeMismatch(
                            "Expected numeric values for > comparison".to_string(),
                        ));
                    }
                }

                NotEq => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;
                    self.set_reg(base, a, Value::bool(!self.values_equal(v1, v2)))?;
                }

                Le => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;

                    if let (Some(n1), Some(n2)) = (v1.as_int(), v2.as_int()) {
                        self.set_reg(base, a, Value::bool(n1 <= n2))?;
                    } else if v1.is_field() && v2.is_field() {
                        let h1 = v1
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let h2 = v2
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let f1 = self
                            .heap
                            .get_field(h1)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        let f2 = self
                            .heap
                            .get_field(h2)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        self.set_reg(base, a, Value::bool(f1.to_canonical() <= f2.to_canonical()))?;
                    } else if v1.is_bigint() && v2.is_bigint() {
                        let (h1, h2) = (
                            v1.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                            v2.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                        );
                        let b1 = self
                            .heap
                            .get_bigint(h1)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        let b2 = self
                            .heap
                            .get_bigint(h2)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        self.set_reg(base, a, Value::bool(b1 <= b2))?;
                    } else {
                        return Err(RuntimeError::TypeMismatch(
                            "Expected numeric values for <= comparison".to_string(),
                        ));
                    }
                }

                Ge => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    let v1 = self.get_reg(base, b)?;
                    let v2 = self.get_reg(base, c)?;

                    if let (Some(n1), Some(n2)) = (v1.as_int(), v2.as_int()) {
                        self.set_reg(base, a, Value::bool(n1 >= n2))?;
                    } else if v1.is_field() && v2.is_field() {
                        let h1 = v1
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let h2 = v2
                            .as_handle()
                            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                        let f1 = self
                            .heap
                            .get_field(h1)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        let f2 = self
                            .heap
                            .get_field(h2)
                            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                        self.set_reg(base, a, Value::bool(f1.to_canonical() >= f2.to_canonical()))?;
                    } else if v1.is_bigint() && v2.is_bigint() {
                        let (h1, h2) = (
                            v1.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                            v2.as_handle().ok_or(RuntimeError::InvalidOperand)?,
                        );
                        let b1 = self
                            .heap
                            .get_bigint(h1)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        let b2 = self
                            .heap
                            .get_bigint(h2)
                            .ok_or(RuntimeError::InvalidOperand)?;
                        self.set_reg(base, a, Value::bool(b1 >= b2))?;
                    } else {
                        return Err(RuntimeError::TypeMismatch(
                            "Expected numeric values for >= comparison".to_string(),
                        ));
                    }
                }

                LogNot => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let vb = self.get_reg(base, b)?;
                    self.set_reg(base, a, Value::bool(vb.is_falsey()))?;
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
                        .ok_or(RuntimeError::SystemError(
                            "MethodCall: method name string missing".into(),
                        ))?
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

                OpCode::GetUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;

                    let closure_idx = self.frames[frame_idx].closure;
                    let closure = self
                        .heap
                        .get_closure(closure_idx)
                        .ok_or(RuntimeError::FunctionNotFound)?;
                    let upval_idx = *closure
                        .upvalues
                        .get(bx)
                        .ok_or(RuntimeError::OutOfBounds("Upvalue index".into()))?;
                    let upval =
                        self.heap
                            .get_upvalue(upval_idx)
                            .ok_or(RuntimeError::SystemError(
                                "Upvalue missing from heap".into(),
                            ))?;

                    let val = match upval.location {
                        memory::UpvalueLocation::Open(stack_idx) => self.get_reg(0, stack_idx)?,
                        memory::UpvalueLocation::Closed(v) => v,
                    };
                    self.set_reg(base, a, val)?;
                }

                SetUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    let val = self.get_reg(base, a)?;

                    let closure_idx = self.frames[frame_idx].closure;
                    let closure = self
                        .heap
                        .get_closure(closure_idx)
                        .ok_or(RuntimeError::FunctionNotFound)?;
                    let upval_idx = *closure
                        .upvalues
                        .get(bx)
                        .ok_or(RuntimeError::OutOfBounds("Upvalue index".into()))?;
                    let upval =
                        self.heap
                            .get_upvalue(upval_idx)
                            .ok_or(RuntimeError::SystemError(
                                "Upvalue missing from heap".into(),
                            ))?;

                    match upval.location {
                        memory::UpvalueLocation::Open(stack_idx) => {
                            self.set_reg(0, stack_idx, val)?;
                        }
                        memory::UpvalueLocation::Closed(_) => {
                            let upval_mut = self.heap.get_upvalue_mut(upval_idx).ok_or(
                                RuntimeError::SystemError("Upvalue missing from heap".into()),
                            )?;
                            upval_mut.location = memory::UpvalueLocation::Closed(val);
                        }
                    }
                }

                CloseUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let stack_idx = base + a;
                    self.close_upvalues(stack_idx)?;
                }

                Closure => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;

                    let proto_idx = *self
                        .prototypes
                        .get(bx)
                        .ok_or(RuntimeError::FunctionNotFound)?;

                    let upval_count = {
                        let proto = self
                            .heap
                            .get_function(proto_idx)
                            .ok_or(RuntimeError::FunctionNotFound)?;
                        let len = proto.upvalue_info.len();
                        if len % 2 != 0 {
                            return Err(RuntimeError::OutOfBounds(format!(
                                "upvalue_info length {len} is not even"
                            )));
                        }
                        len
                    };

                    self.heap.lock_gc();
                    let mut captured = Vec::with_capacity(upval_count / 2);
                    let mut i = 0;
                    let capture_result: Result<(), RuntimeError> = (|| {
                        while i < upval_count {
                            let (is_local, index) = {
                                let proto = self
                                    .heap
                                    .get_function(proto_idx)
                                    .ok_or(RuntimeError::FunctionNotFound)?;
                                (
                                    proto.upvalue_info[i] == 1,
                                    proto.upvalue_info[i + 1] as usize,
                                )
                            };
                            i += 2;

                            if is_local {
                                let stack_idx = base + index;
                                let upval_idx = self.capture_upvalue(stack_idx)?;
                                captured.push(upval_idx);
                            } else {
                                let current_closure_idx = self.frames[frame_idx].closure;
                                let current_closure = self
                                    .heap
                                    .get_closure(current_closure_idx)
                                    .ok_or(RuntimeError::FunctionNotFound)?;
                                let upval_idx = *current_closure
                                    .upvalues
                                    .get(index)
                                    .ok_or(RuntimeError::OutOfBounds("Upvalue capture".into()))?;
                                captured.push(upval_idx);
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = capture_result {
                        self.heap.unlock_gc();
                        return Err(e);
                    }

                    let closure = memory::Closure {
                        function: proto_idx,
                        upvalues: captured,
                    };
                    let closure_idx = self.heap.alloc_closure(closure)?;
                    self.heap.unlock_gc();
                    self.set_reg(base, a, Value::closure(closure_idx))?;
                }

                OpCode::GetIter => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let val = self.get_reg(base, b)?;

                    if val.is_iter() {
                        self.set_reg(base, a, val)?;
                    } else {
                        let iter_obj = if val.is_list() {
                            // Snapshot: clone list contents so mutations during
                            // iteration don't cause stale reads or OOB access.
                            let l_handle = val.as_handle().ok_or_else(|| {
                                RuntimeError::TypeMismatch("Expected list handle".into())
                            })?;
                            let snapshot = self
                                .heap
                                .get_list(l_handle)
                                .ok_or(RuntimeError::SystemError("List missing".into()))?
                                .clone();
                            let snap_handle = self.heap.alloc_list(snapshot)?;
                            memory::IteratorObj {
                                source: Value::list(snap_handle),
                                index: 0,
                            }
                        } else if val.is_map() {
                            let handle = val.as_handle().ok_or_else(|| {
                                RuntimeError::TypeMismatch("Expected map handle".into())
                            })?;
                            let map_keys: Vec<String> = {
                                let map = self
                                    .heap
                                    .get_map(handle)
                                    .ok_or(RuntimeError::SystemError("Map missing".into()))?;
                                map.keys().cloned().collect()
                            };

                            self.heap.lock_gc();
                            let mut val_keys = Vec::with_capacity(map_keys.len());
                            for s in map_keys {
                                let handle = if let Some(&h) = self.interner.get(&s) {
                                    h
                                } else {
                                    let h = self.heap.alloc_string(s.clone())?;
                                    self.interner.insert(s, h);
                                    h
                                };
                                val_keys.push(Value::string(handle));
                            }

                            let list_handle = self.heap.alloc_list(val_keys)?;
                            self.heap.unlock_gc();
                            memory::IteratorObj {
                                source: Value::list(list_handle),
                                index: 0,
                            }
                        } else {
                            return Err(RuntimeError::TypeMismatch(format!(
                                "Value not iterable: {:?}",
                                val
                            )));
                        };

                        let handle = self.heap.alloc_iterator(iter_obj)?;
                        self.set_reg(base, a, Value::iterator(handle))?;
                    }
                }

                OpCode::ForIter => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;

                    if bx > chunk_len {
                        return Err(RuntimeError::OutOfBounds(format!(
                            "ForIter exit target {bx} exceeds chunk length {chunk_len}"
                        )));
                    }
                    if a + 1 >= max_slots {
                        return Err(RuntimeError::StackOverflow);
                    }

                    let iter_val = self.get_reg(base, a)?;
                    if !iter_val.is_iter() {
                        return Err(RuntimeError::TypeMismatch(
                            "Expected iterator for loop".into(),
                        ));
                    }
                    let iter_handle = iter_val.as_handle().ok_or_else(|| {
                        RuntimeError::TypeMismatch("Expected iterator handle".into())
                    })?;

                    let (source, index) = {
                        let iter = self
                            .heap
                            .get_iterator(iter_handle)
                            .ok_or(RuntimeError::SystemError("Iterator missing".into()))?;
                        (iter.source, iter.index)
                    };

                    let mut next_val = None;

                    if source.is_list() {
                        let l_handle = source.as_handle().ok_or_else(|| {
                            RuntimeError::TypeMismatch("Expected list handle".into())
                        })?;
                        if let Some(list) = self.heap.get_list(l_handle) {
                            if index < list.len() {
                                next_val = Some(list[index]);
                            }
                        }
                    }

                    if let Some(val) = next_val {
                        if let Some(iter) = self.heap.get_iterator_mut(iter_handle) {
                            iter.index += 1;
                        }
                        self.set_reg(base, a + 1, val)?;
                    } else {
                        self.frames[frame_idx].ip = bx;
                    }
                }

                Nop => { /* no-op */ }
            }
        }
        Ok(())
    }
}
