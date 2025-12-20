use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::native::NativeObj;
use crate::opcode::{instruction::*, OpCode};
use memory::{Heap, Value, Closure, Upvalue};
use std::collections::HashMap;
use std::ptr;

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
    
    // Passive Debug Symbols (Sidecar)
    pub debug_symbols: Option<HashMap<u16, String>>,
}

pub const STACK_MAX: usize = 65_536;

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
            debug_symbols: None,
        };

        // Bootstrap native functions
        vm.bootstrap_natives();

        vm
    }

    /// Soft Reset: Clears stack and frames for REPL/Running new script.
    /// CRITICAL: Must close all open upvalues to prevent them from pointing to dead stack slots.
    pub fn reset(&mut self) {
        // 1. Close ALL open upvalues
        let stack_start = self.stack.as_ptr() as *mut Value;
        self.close_upvalues(stack_start);
        
        // 2. Clear Runtime State
        self.frames.clear();
        self.open_upvalues = None;
        // We don't need to zero the stack, just reset pointers if we had them.
        // But since we write registers before reading, it's generally fine.
        // For safety/debug, we could nil it, but it's expensive O(N).
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
            let closure = self.heap.get_closure(frame.closure).ok_or(RuntimeError::FunctionNotFound)?;
            let func = self.heap.get_function(closure.function).ok_or(RuntimeError::FunctionNotFound)?;
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

            let func = {
                let closure = self.heap.get_closure(closure_idx).ok_or(RuntimeError::FunctionNotFound)?;
                self.heap.get_function(closure.function).ok_or(RuntimeError::FunctionNotFound)?
            };

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



                GetUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    
                    let closure_idx = self.frames[frame_idx].closure;
                    let closure = self.heap.get_closure(closure_idx).ok_or(RuntimeError::FunctionNotFound)?;
                    let upval_idx = *closure.upvalues.get(bx).ok_or(RuntimeError::OutOfBounds("Upvalue index".into()))?;
                    let upval = self.heap.get_upvalue(upval_idx).ok_or(RuntimeError::SystemError("Upvalue missing from heap".into()))?;
                    
                    // SAFETY: location points to Stack or Closed Value.
                    // If Closed, location points to &upval.closed. Address is stable (Box).
                    // If Open, location points to Stack (fixed Box<[Value]>).
                    let val = unsafe { *upval.location };
                    self.set_reg(base, a, val);
                }

                SetUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize;
                    let val = self.get_reg(base, a);
                    
                    let closure_idx = self.frames[frame_idx].closure;
                    let closure = self.heap.get_closure(closure_idx).ok_or(RuntimeError::FunctionNotFound)?;
                    let upval_idx = *closure.upvalues.get(bx).ok_or(RuntimeError::OutOfBounds("Upvalue index".into()))?;
                    
                    // We need mutable access to location
                    let upval = self.heap.get_upvalue_mut(upval_idx).ok_or(RuntimeError::SystemError("Upvalue missing from heap".into()))?;
                    unsafe { *upval.location = val; }
                }

                CloseUpvalue => {
                    let a = decode_a(instruction) as usize;
                    let ptr = self.get_reg_ptr(base, a)?; // Get addr of R[A]
                    self.close_upvalues(ptr);
                }

                Closure => {
                    let a = decode_a(instruction) as usize;
                    let bx = decode_bx(instruction) as usize; // Index into prototypes

                    // 1. Get Prototype Info (Scope check)
                    // We avoid cloning the vector by fetching length first, then iterating.
                    // We can't hold reference to 'proto' while mutating heap.
                    let (upval_count, _max_slots) = {
                        let proto_idx = self.prototypes.get(bx).ok_or(RuntimeError::FunctionNotFound)?;
                        let proto = self.heap.get_function(*proto_idx).ok_or(RuntimeError::FunctionNotFound)?;
                        (proto.upvalue_info.len(), proto.max_slots)
                    };

                    let proto_idx = self.prototypes[bx];

                    // 2. Capture Upvalues
                    let mut captured = Vec::with_capacity(upval_count / 2);
                    let mut i = 0;
                    while i < upval_count {
                        // Optimization: Fetch just the 2 bytes we need for this step
                        let (is_local, index) = {
                             let proto = self.heap.get_function(proto_idx).ok_or(RuntimeError::FunctionNotFound)?;
                             (proto.upvalue_info[i] == 1, proto.upvalue_info[i+1] as usize)
                        };
                        i += 2;

                        if is_local {
                            // Capture from current frame
                            // base is reg[0] of current frame
                            let ptr = self.get_reg_ptr(base, index)?;
                            let upval_idx = self.capture_upvalue(ptr);
                            captured.push(upval_idx);
                        } else {
                            // Capture from surrounding closure (upvalue of current closure)
                            let current_closure_idx = self.frames[frame_idx].closure;
                            let current_closure = self.heap.get_closure(current_closure_idx).ok_or(RuntimeError::FunctionNotFound)?;
                            let upval_idx = *current_closure.upvalues.get(index).ok_or(RuntimeError::OutOfBounds("Upvalue capture".into()))?;
                            captured.push(upval_idx);
                        }
                    }

                    // 3. Create Closure Object
                    let closure = memory::Closure {
                        function: proto_idx,
                        upvalues: captured,
                    };
                    let closure_idx = self.heap.alloc_closure(closure);
                    self.set_reg(base, a, Value::closure(closure_idx));
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

    /// Secure pointer access with bounds checking (Fix DoS)
    pub fn get_reg_ptr(&self, base: usize, offset: usize) -> Result<*mut Value, RuntimeError> {
        let index = base + offset;
        if index >= self.stack.len() {
             return Err(RuntimeError::OutOfBounds(format!("Stack index {} out of bounds", index)));
        }
        // SAFETY: Bounds checked. Box<[Value]> has stable address.
        Ok(unsafe { self.stack.as_ptr().wrapping_add(index) as *mut Value })
    }

    /// Capture an upvalue for a local variable residing on the stack.
    fn capture_upvalue(&mut self, local: *mut Value) -> u32 {
        let mut prev_upval_idx: Option<u32> = None;
        let mut upval_idx = self.open_upvalues;

        while let Some(idx) = upval_idx {
            let upval = self.heap.get_upvalue(idx).unwrap();
            
            // List is sorted by location (High -> Low, typically)
            // If upval.location < local: We passed the insertion point
            // If upval.location == local: Found it
            
            if upval.location == local {
                return idx;
            }
            
            // Assuming Stack grows Up (addresses increase).
            // Lua sorts list by stack level (Top/High -> Bottom/Low).
            // So Head is Highest Address.
            // If current (High) > local, we proceed.
            // If current (Low) < local, we found spot (because we want to insert 'local' which is Higher than current).
            // So loop while upval.location > local
            
            if upval.location < local {
                break;
            }

            prev_upval_idx = Some(idx);
            upval_idx = upval.next_open;
        }

        // Not found, create new
        let created_upval = Upvalue {
            location: local,
            closed: Value::nil(),
            next_open: upval_idx, // Link to next (lower)
        };
        let new_idx = self.heap.alloc_upvalue(created_upval);

        if let Some(prev) = prev_upval_idx {
             // Link prev -> new
             let prev_obj = self.heap.get_upvalue_mut(prev).unwrap();
             prev_obj.next_open = Some(new_idx);
        } else {
             // Link Head -> new
             self.open_upvalues = Some(new_idx);
        }
        
        new_idx
    }

    pub fn close_upvalues(&mut self, last: *mut Value) {
        // Close all upvalues >= last
        // Iterate open_upvalues.
        // If upval.location >= last:
        //   Move From Stack To Closed
        //   Point location to &closed
        //   Remove from list
        
        while let Some(idx) = self.open_upvalues {
            let upval = self.heap.get_upvalue(idx).unwrap();
            
            if upval.location >= last {
                // Move value
                let captured_val = unsafe { *upval.location };
                
                // We need mut access to close it
                let upval_mut = self.heap.get_upvalue_mut(idx).unwrap();
                upval_mut.closed = captured_val;
                upval_mut.location = &mut upval_mut.closed as *mut Value;
                
                // Update Head to next
                let next = upval_mut.next_open;
                self.open_upvalues = next;
            } else {
                // List is sorted High -> Low.
                // If current < last, then all subsequent are < last.
                // We can stop.
                break;
            }
        }
    }
}
