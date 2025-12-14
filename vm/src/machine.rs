
use crate::opcode::{OpCode, instruction::*};
use crate::native::{NativeObj, NativeFn};
use crate::error::RuntimeError;
use memory::{Heap, Value, value::{TAG_NUMBER, TAG_COMPLEX, TAG_NATIVE, TAG_FUNCTION}};
use num_complex::Complex64;
use std::collections::HashMap;

pub struct CallFrame {
    pub closure: u32,
    pub ip: usize,
    pub base: usize,
}

use crate::globals::GlobalEntry;
pub struct VM {
    pub heap: Heap,
    pub stack: Vec<Value>, 
    pub frames: Vec<CallFrame>,
    pub globals: HashMap<u32, GlobalEntry>,
    pub interner: HashMap<String, u32>,
    pub natives: Vec<NativeObj>,
}

impl VM {
    pub fn new() -> Self {
        let mut vm = Self {
            heap: Heap::new(),
            stack: Vec::with_capacity(2048),
            frames: Vec::with_capacity(64),
            globals: HashMap::new(),
            interner: HashMap::new(),
            natives: Vec::new(),
        };

        // Preamble: Core Intrinsics
        vm.define_native("print", crate::stdlib::core::native_print, -1);
        vm.define_native("len", crate::stdlib::core::native_len, 1);
        vm.define_native("typeof", crate::stdlib::core::native_typeof, 1);
        vm.define_native("assert", crate::stdlib::core::native_assert, 1); // 1 arg implementation
        
        vm
    }

    pub fn define_native(&mut self, name: &str, func: NativeFn, arity: isize) {
        let name_string = name.to_string();
        
        // 1. Intern string (ensure it exists in Heap and Interner)
        let name_handle = if let Some(&h) = self.interner.get(&name_string) {
            h
        } else {
            let h = self.heap.alloc_string(name_string.clone());
            self.interner.insert(name_string.clone(), h);
            h
        };

        // 2. Register Native Object
        let native = NativeObj {
            name: name_string,
            func,
            arity,
        };
        self.natives.push(native);
        let native_idx = (self.natives.len() - 1) as u32;
        
        // 3. Register in Globals
        let val = Value::native(native_idx);
        self.globals.insert(name_handle, GlobalEntry {
            value: val,
            mutable: false, // Natives are constant
        });
    }
    
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
             
             let func = self.heap.get_function(closure_idx)
                 .ok_or(RuntimeError::FunctionNotFound)?;
             
             if ip >= func.chunk.len() {
                 self.frames.pop();
                 continue;
             }
             
             let instruction = func.chunk[ip];
             self.frames[frame_idx].ip += 1;
             
             let op_byte = decode_opcode(instruction);
             let op = OpCode::from_u8(op_byte).ok_or(RuntimeError::InvalidOpcode(op_byte))?;
             
             match op {
                 OpCode::LoadConst => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     let val = func.constants.get(bx).cloned().unwrap_or(Value::nil());
                     self.set_reg(base, a, val);
                 },
                OpCode::Move => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let val = self.get_reg(base, b);
                    self.set_reg(base, a, val);
                },

                 OpCode::Add => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     let res = self.binary_op(vb, vc, |x, y| x + y, |x, y| x + y)?;
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Sub => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     let res = self.binary_op(vb, vc, |x, y| x - y, |x, y| x - y)?;
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Mul => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     let res = self.binary_op(vb, vc, |x, y| x * y, |x, y| x * y)?;
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Div => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     let res = self.binary_op(vb, vc, |x, y| x / y, |x, y| x / y)?;
                     self.set_reg(base, a, res);
                 },

                 OpCode::Pow => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     
                     if vb.is_number() && vc.is_number() {
                          let x = vb.as_number().unwrap();
                          let y = vc.as_number().unwrap();
                          
                          let res_real = x.powf(y);
                          if res_real.is_nan() && x < 0.0 {
                              // Promotion case: (-4)^0.5 = 2i
                              let cx = Complex64::new(x, 0.0);
                              let cy = Complex64::new(y, 0.0);
                              let res_complex = cx.powc(cy);
                              // Alloc complex
                              let res = Value::complex(self.heap.alloc_complex(res_complex));
                              self.set_reg(base, a, res);
                          } else {
                              // Standard real result
                              self.set_reg(base, a, Value::number(res_real));
                          }
                     } else {
                          // Fallback to standard binary_op for Complex mixed cases which handles promotion
                          let res = self.binary_op(vb, vc, |x, y| x.powf(y), |x, y| x.powc(y))?;
                          self.set_reg(base, a, res);
                     }
                 },
                 
                 OpCode::Neg => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let res = if vb.is_number() {
                         Value::number(-vb.as_number().unwrap())
                     } else if vb.is_complex() {
                         let idx = vb.as_handle().unwrap();
                         let c = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                         let neg = -c;
                         Value::complex(self.heap.alloc_complex(neg))
                     } else {
                         return Err(RuntimeError::TypeMismatch("Neg".into()));
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Sqrt => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let res = if vb.is_number() {
                         let n = vb.as_number().unwrap();
                         if n < 0.0 {
                             let c = Complex64::new(0.0, (-n).sqrt());
                             Value::complex(self.heap.alloc_complex(c))
                         } else {
                             Value::number(n.sqrt())
                         }
                     } else if vb.is_complex() {
                         let idx = vb.as_handle().unwrap();
                         let c = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                         let sqrt_c = c.sqrt();
                         Value::complex(self.heap.alloc_complex(sqrt_c))
                     } else {
                         return Err(RuntimeError::TypeMismatch("Sqrt".into()));
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::NewComplex => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     
                     let re = if vb.is_number() { vb.as_number().unwrap() } else { return Err(RuntimeError::TypeMismatch("NewComplex: real part must be Number".into())); };
                     let im = if vc.is_number() { vc.as_number().unwrap() } else { return Err(RuntimeError::TypeMismatch("NewComplex: imag part must be Number".into())); };
                     
                     let c = Complex64::new(re, im);
                     let res = Value::complex(self.heap.alloc_complex(c));
                     self.set_reg(base, a, res);
                 },
                OpCode::Call => {
                    let a = decode_a(instruction) as usize;
                    let b = decode_b(instruction) as usize;
                    let c = decode_c(instruction) as usize;
                    
                    let func_val = self.get_reg(base, b);
                    let args_start = base + b + 1;
                    let args_count = c;

                    if args_start + args_count > self.stack.len() {
                        return Err(RuntimeError::StackUnderflow);
                    }

                    if func_val.is_native() {
                        let handle = func_val.as_handle().unwrap();
                        let (func, arity) = {
                            let n = self.natives.get(handle as usize).ok_or(RuntimeError::FunctionNotFound)?;
                            (n.func, n.arity)
                        };

                        if arity != -1 && arity as usize != args_count {
                            return Err(RuntimeError::ArityMismatch(format!("Expected {} args, got {}", arity, args_count)));
                        }

                        let args: Vec<Value> = self.stack[args_start .. args_start + args_count].to_vec();
                        let res = func(self, &args)?;
                        self.set_reg(base, a, res);
                    } else if func_val.is_function() {
                        return Err(RuntimeError::Unknown("Script function calls not implemented yet".into()));
                    } else {
                        return Err(RuntimeError::TypeMismatch("Call target must be Function or Native".into()));
                    }
                },
                 OpCode::Return => {
                     let a = decode_a(instruction) as usize;
                     let _ret_val = self.get_reg(base, a);
                     self.frames.pop();
                 },

                 // ===== Global Variables =====
                 OpCode::DefGlobalVar | OpCode::DefGlobalLet => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     let val = self.get_reg(base, a);
                     
                     let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                     if !c.is_string() {
                         return Err(RuntimeError::TypeMismatch("Global name must be a string handle".into()));
                     }
                     let name_handle = c.as_handle().unwrap();
                     
                     let mutable = op == OpCode::DefGlobalVar;
                     self.globals.insert(name_handle, GlobalEntry { value: val, mutable });
                 },
                 
                 OpCode::GetGlobal => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     
                     let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                     if !c.is_string() {
                         return Err(RuntimeError::TypeMismatch("Global name must be a string handle".into()));
                     }
                     let name_handle = c.as_handle().unwrap();
                     
                     if let Some(entry) = self.globals.get(&name_handle) {
                         self.set_reg(base, a, entry.value.clone());
                     } else {
                         let name = self.heap.get_string(name_handle).cloned().unwrap_or("???".to_string());
                         return Err(RuntimeError::Unknown(format!("Undefined global variable: {}", name)));
                     }
                 },
                 
                 OpCode::SetGlobal => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     let val = self.get_reg(base, a);
                     
                     let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                     if !c.is_string() {
                         return Err(RuntimeError::TypeMismatch("Global name must be a string handle".into()));
                     }
                     let name_handle = c.as_handle().unwrap();
                     
                     if let Some(entry) = self.globals.get_mut(&name_handle) {
                         if entry.mutable {
                             entry.value = val;
                         } else {
                             let name = self.heap.get_string(name_handle).cloned().unwrap_or("???".to_string());
                             return Err(RuntimeError::Unknown(format!("Cannot assign to immutable global '{}'", name)));
                         }
                     } else {
                         let name = self.heap.get_string(name_handle).cloned().unwrap_or("???".to_string());
                         return Err(RuntimeError::Unknown(format!("Undefined global variable: {}", name)));
                     }
                 },

                 OpCode::Print => {
                     let a = decode_a(instruction) as usize;
                     let val = self.get_reg(base, a);
                     // Simple debug print for now
                     println!("{:?}", val);
                 },
                 
                 _ => return Err(RuntimeError::Unknown(format!("Unimplemented opcode {:?}", op))),
             }
        }
        Ok(())
    }
    
    /// Binary operation with automatic Real<->Complex promotion
    /// Uses direct f64 for Number+Number to preserve IEEE754 semantics
    fn binary_op<F, G>(&mut self, left: Value, right: Value, f64_op: F, complex_op: G) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
        G: Fn(Complex64, Complex64) -> Complex64,
    {
        match (left.type_tag(), right.type_tag()) {
            (TAG_NUMBER, TAG_NUMBER) => {
                let a = left.as_number().unwrap();
                let b = right.as_number().unwrap();
                Ok(Value::number(f64_op(a, b)))
            }
            (TAG_NUMBER, TAG_COMPLEX) => {
                let a = left.as_number().unwrap();
                let idx = right.as_handle().unwrap();
                let cb = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                let ca = Complex64::new(a, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            (TAG_COMPLEX, TAG_NUMBER) => {
                let idx = left.as_handle().unwrap();
                let ca = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                let b = right.as_number().unwrap();
                let cb = Complex64::new(b, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            (TAG_COMPLEX, TAG_COMPLEX) => {
                let idx_a = left.as_handle().unwrap();
                let idx_b = right.as_handle().unwrap();
                let ca = self.heap.get_complex(idx_a).ok_or(RuntimeError::InvalidOperand)?;
                let cb = self.heap.get_complex(idx_b).ok_or(RuntimeError::InvalidOperand)?;
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            _ => Err(RuntimeError::TypeMismatch("Operands must be numeric".into()))
        }
    }
    
    fn get_reg(&self, base: usize, reg: usize) -> Value {
        self.stack.get(base + reg).cloned().unwrap_or(Value::nil())
    }
    
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) {
        let idx = base + reg;
        if idx >= self.stack.len() {
            self.stack.resize(idx + 1, Value::nil());
        }
        self.stack[idx] = val;
    }

    pub fn collect_garbage(&mut self) {
        let _before = self.heap.bytes_allocated;
        // println!("-- GC Begin (Allocated: {} bytes) --", before);
        
        let roots = self.mark_roots();
        self.heap.trace(roots);
        self.heap.sweep();
        
        // Dynamic Threshold: Double it or set reasonable limits
        self.heap.next_gc_threshold = std::cmp::max(
            self.heap.bytes_allocated * 2,
            1024 * 1024 // Min 1MB
        );
    }

    fn mark_roots(&self) -> Vec<Value> {
        let mut roots = Vec::new();
        
        // 1. Stack
        roots.extend_from_slice(&self.stack);
        
        // 2. Globals
        for entry in self.globals.values() {
            roots.push(entry.value);
        }
        
        // 3. Call Frames (Closures/Functions)
        for frame in &self.frames {
            roots.push(Value::function(frame.closure));
        }
        
        roots
    }
}
