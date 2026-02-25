use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::native::NativeObj;
use crate::opcode::{instruction::*, OpCode};
use memory::{Heap, Upvalue, Value};
use std::collections::HashMap;

use super::arithmetic::ArithmeticOps;
use super::control::ControlFlowOps;
use super::data::DataOps;
use super::frame::CallFrame;
use super::gc::GarbageCollector;
use super::globals::GlobalOps;
use super::native::NativeRegistry;
use super::prove::{ProveHandler, VerifyHandler};
use super::stack::StackOps;

/// The Virtual Machine struct
pub struct VM {
    pub heap: Heap,
    // SAFETY: Box<[Value]> guarantees stable address (no reallocation)
    pub stack: Box<[Value]>,
    pub frames: Vec<CallFrame>,
    pub globals: Vec<GlobalEntry>,
    pub interner: HashMap<String, u32>,
    pub natives: Vec<NativeObj>,

    /// Function prototypes (handles) for O(1) CLOSURE lookup
    pub prototypes: Vec<u32>,

    /// Head of the linked list of open upvalues (Index into Heap.upvalues)
    pub open_upvalues: Option<u32>,

    /// If true, GC will run on every possible occasion (for testing)
    pub stress_mode: bool,

    // Passive Debug Symbols (Sidecar)
    pub debug_symbols: Option<HashMap<u16, String>>,

    /// Handler for `prove { }` blocks (injected by CLI or host)
    pub prove_handler: Option<Box<dyn ProveHandler>>,

    /// Handler for `verify_proof()` calls (injected by CLI or host)
    pub verify_handler: Option<Box<dyn VerifyHandler>>,
}

pub const STACK_MAX: usize = 65_536;

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

impl VM {
    /// Create a new VM instance with bootstrapped native functions
    pub fn new() -> Self {
        // Pre-allocate fixed-size stack and PIN it via Box
        let stack = vec![Value::nil(); STACK_MAX].into_boxed_slice();

        let mut vm = Self {
            heap: Heap::new(),
            stack,
            frames: Vec::with_capacity(64),
            globals: Vec::with_capacity(64),
            interner: HashMap::new(),
            natives: Vec::new(),
            prototypes: Vec::new(),
            open_upvalues: None,
            stress_mode: false,
            debug_symbols: None,
            prove_handler: None,
            verify_handler: None,
        };

        // Bootstrap native functions
        vm.bootstrap_natives();

        vm
    }

    /// Soft Reset: Clears stack and frames for REPL/Running new script.
    /// CRITICAL: Must close all open upvalues to prevent them from pointing to dead stack slots.
    pub fn reset(&mut self) {
        // 1. Close ALL open upvalues (stack index 0 = everything)
        self.close_upvalues(0);

        // 2. Clear Runtime State
        self.frames.clear();
        self.open_upvalues = None;

        // 3. Zero stack in debug builds to prevent stale values leaking
        #[cfg(debug_assertions)]
        self.stack.fill(Value::nil());
    }

    /// Helper to format values for display (Clean UX)
    pub fn val_to_string(&self, val: &Value) -> String {
        match val {
            v if v.is_string() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad string>".into();
                };
                self.heap
                    .get_string(handle)
                    .cloned()
                    .unwrap_or("<bad string>".into())
            }
            v if v.is_int() => format!("{}", v.as_int().unwrap()),
            v if v.is_bool() => format!("{}", v.as_bool().unwrap()),
            v if v.is_nil() => "nil".to_string(),
            v if v.is_field() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad field>".into();
                };
                match self.heap.get_field(handle) {
                    Some(fe) => format!("Field({})", fe.to_decimal_string()),
                    None => "<bad field>".into(),
                }
            }
            v if v.is_proof() => "<Proof>".to_string(),
            v if v.is_list() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad list>".into();
                };
                format!("[List:{}]", handle)
            }
            v if v.is_map() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad map>".into();
                };
                format!("{{Map:{}}}", handle)
            }
            _ => format!("{:?}", val), // Fallback
        }
    }

    /// Deep equality check for runtime values
    pub fn values_equal(&self, v1: Value, v2: Value) -> bool {
        if v1 == v2 {
            return true; // Same identity (or primitive value)
        }

        if v1.is_string() && v2.is_string() {
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            let s1 = self.heap.get_string(h1);
            let s2 = self.heap.get_string(h2);
            match (s1, s2) {
                (Some(str1), Some(str2)) => str1 == str2,
                _ => false,
            }
        } else if v1.is_field() && v2.is_field() {
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            match (self.heap.get_field(h1), self.heap.get_field(h2)) {
                (Some(f1), Some(f2)) => f1 == f2,
                _ => false,
            }
        } else if v1.is_proof() && v2.is_proof() {
            // Proof equality is structural: two proofs are equal iff all three
            // JSON components match byte-for-byte. This is intentional — Groth16
            // proofs include randomness, so different proofs for the same circuit
            // and inputs will not compare equal. This matches the semantics of
            // "same proof object" rather than "same statement proven".
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            match (self.heap.get_proof(h1), self.heap.get_proof(h2)) {
                (Some(p1), Some(p2)) => {
                    p1.proof_json == p2.proof_json
                        && p1.public_json == p2.public_json
                        && p1.vkey_json == p2.vkey_json
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Main interpretation loop
    pub fn interpret(&mut self) -> Result<(), RuntimeError> {
        // Validation: Check checking initial frame fits

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

        while !self.frames.is_empty() {
            // GC Check Point
            // If allocations happened, heap.request_gc might be set
            if self.heap.request_gc || self.stress_mode {
                self.collect_garbage();
                self.heap.request_gc = false;
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
            self.frames[frame_idx].ip += 1;

            let op_byte = decode_opcode(instruction);
            let op = OpCode::from_u8(op_byte).ok_or(RuntimeError::InvalidOpcode(op_byte))?;

            // Inline dispatch to avoid borrow conflicts
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
                    self.frames[frame_idx].ip = dest;
                }

                JumpIfFalse => {
                    let a = decode_a(instruction) as usize;
                    let dest = decode_bx(instruction) as usize;
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
                    let val = func.constants.get(bx).cloned().unwrap_or(Value::nil());
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
                    self.close_upvalues(stack_idx);
                }

                Closure => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize; // Index into prototypes

                    // 1. Get Prototype Info (Scope check)
                    // We avoid cloning the vector by fetching length first, then iterating.
                    // We can't hold reference to 'proto' while mutating heap.
                    let (upval_count, _max_slots) = {
                        let proto_idx = self
                            .prototypes
                            .get(bx)
                            .ok_or(RuntimeError::FunctionNotFound)?;
                        let proto = self
                            .heap
                            .get_function(*proto_idx)
                            .ok_or(RuntimeError::FunctionNotFound)?;
                        (proto.upvalue_info.len(), proto.max_slots)
                    };

                    let proto_idx = self.prototypes[bx];

                    // 2. Capture Upvalues
                    let mut captured = Vec::with_capacity(upval_count / 2);
                    let mut i = 0;
                    while i < upval_count {
                        // Optimization: Fetch just the 2 bytes we need for this step
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
                            // Capture from current frame (base + index = absolute stack slot)
                            let stack_idx = base + index;
                            let upval_idx = self.capture_upvalue(stack_idx);
                            captured.push(upval_idx);
                        } else {
                            // Capture from surrounding closure (upvalue of current closure)
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

                    // 3. Create Closure Object
                    let closure = memory::Closure {
                        function: proto_idx,
                        upvalues: captured,
                    };
                    let closure_idx = self.heap.alloc_closure(closure);
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
                            let snap_handle = self.heap.alloc_list(snapshot);
                            memory::IteratorObj {
                                source: Value::list(snap_handle),
                                index: 0,
                            }
                        } else if val.is_map() {
                            // Convert Map keys to a snapshot list.
                            // Keys are collected in an inner block to end the map
                            // borrow before any heap allocations.
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

                            let mut val_keys = Vec::with_capacity(map_keys.len());
                            for s in map_keys {
                                // Intern
                                let handle = if let Some(&h) = self.interner.get(&s) {
                                    h
                                } else {
                                    let h = self.heap.alloc_string(s.clone());
                                    self.interner.insert(s, h);
                                    h
                                };
                                val_keys.push(Value::string(handle));
                            }

                            let list_handle = self.heap.alloc_list(val_keys);
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

                        let handle = self.heap.alloc_iterator(iter_obj);
                        self.set_reg(base, a, Value::iterator(handle))?;
                    }
                }

                OpCode::ForIter => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;

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

                    // Split borrow: Get state, then access source, then update state
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
                    // Maps are converted to Lists in GetIter, so they fall into is_list() above.

                    if let Some(val) = next_val {
                        // Update Iterator Index
                        if let Some(iter) = self.heap.get_iterator_mut(iter_handle) {
                            iter.index += 1;
                        }
                        // Set Loop Variable at R[A+1]
                        self.set_reg(base, a + 1, val)?;
                    } else {
                        // Done. Jump to Exit (Bx is absolute IP)
                        self.frames[frame_idx].ip = bx;
                    }
                }

                Nop => { /* no-op */ }
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

    /// Capture an upvalue for a local variable at `stack_idx` (absolute index).
    fn capture_upvalue(&mut self, stack_idx: usize) -> u32 {
        let mut prev_upval_idx: Option<u32> = None;
        let mut upval_idx = self.open_upvalues;

        while let Some(idx) = upval_idx {
            let upval = self.heap.get_upvalue(idx).unwrap();

            // Open upvalue list is sorted by stack index (high → low).
            let loc = match upval.location {
                memory::UpvalueLocation::Open(si) => si,
                _ => break, // should not happen in open list
            };

            if loc == stack_idx {
                return idx; // already captured
            }

            if loc < stack_idx {
                break; // insertion point found
            }

            prev_upval_idx = Some(idx);
            upval_idx = upval.next_open;
        }

        // Not found — create new open upvalue
        let created_upval = Upvalue {
            location: memory::UpvalueLocation::Open(stack_idx),
            next_open: upval_idx, // link to next (lower index)
        };
        let new_idx = self.heap.alloc_upvalue(created_upval);

        if let Some(prev) = prev_upval_idx {
            let prev_obj = self.heap.get_upvalue_mut(prev).unwrap();
            prev_obj.next_open = Some(new_idx);
        } else {
            self.open_upvalues = Some(new_idx);
        }

        new_idx
    }

    /// Close all open upvalues pointing at stack index >= `last`.
    /// Copies the stack value into the upvalue and marks it Closed.
    pub fn close_upvalues(&mut self, last: usize) {
        while let Some(idx) = self.open_upvalues {
            let upval = self.heap.get_upvalue(idx).unwrap();

            let stack_idx = match upval.location {
                memory::UpvalueLocation::Open(si) => si,
                _ => break,
            };

            if stack_idx >= last {
                // Capture value from stack
                let captured_val = self.stack.get(stack_idx).copied().unwrap_or(Value::nil());

                let upval_mut = self.heap.get_upvalue_mut(idx).unwrap();
                upval_mut.location = memory::UpvalueLocation::Closed(captured_val);

                let next = upval_mut.next_open;
                self.open_upvalues = next;
            } else {
                // List is sorted high → low; all remaining are < last.
                break;
            }
        }
    }
}
