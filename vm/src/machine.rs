
use crate::opcode::{OpCode, instruction::*};
use crate::error::RuntimeError;
use memory::{Heap, Value};
use num_complex::Complex64;
use std::collections::HashMap;

pub struct CallFrame {
    pub closure: u32,
    pub ip: usize,
    pub base: usize,
}

#[derive(Clone, Debug)]
pub struct GlobalEntry {
    pub value: Value,
    pub mutable: bool,
}

pub struct VM {
    pub heap: Heap,
    pub stack: Vec<Value>, 
    pub frames: Vec<CallFrame>,
    pub globals: HashMap<String, GlobalEntry>,
    pub interner: HashMap<String, u32>,
}

impl VM {
    pub fn new() -> Self {
        Self {
            heap: Heap::new(),
            stack: Vec::with_capacity(2048),
            frames: Vec::with_capacity(64),
            globals: HashMap::new(),
            interner: HashMap::new(),
        }
    }
    
    pub fn interpret(&mut self) -> Result<(), RuntimeError> {
        while !self.frames.is_empty() {
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
                     let val = func.constants.get(bx).cloned().unwrap_or(Value::Nil);
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
                     
                     // Custom handling for Pow to support (-1)^0.5 -> Complex
                     // We can't use standard binary_op blindly because typical f64::powf returns NaN for negative base
                     match (&vb, &vc) {
                         (Value::Number(x), Value::Number(y)) => {
                             // Try real power first
                             let res_real = x.powf(*y);
                             if res_real.is_nan() && *x < 0.0 {
                                 // Promotion case: (-4)^0.5 = 2i
                                 let cx = Complex64::new(*x, 0.0);
                                 let cy = Complex64::new(*y, 0.0);
                                 let res_complex = cx.powc(cy);
                                 // Alloc complex
                                 let res = Value::Complex(self.heap.alloc_complex(res_complex));
                                 self.set_reg(base, a, res);
                             } else {
                                 // Standard real result (might be NaN for other reasons like 0/0, that's fine)
                                 self.set_reg(base, a, Value::Number(res_real));
                             }
                         }
                         _ => {
                             // Fallback to standard binary_op for Complex mixed cases which handles promotion
                             let res = self.binary_op(vb, vc, |x, y| x.powf(y), |x, y| x.powc(y))?;
                             self.set_reg(base, a, res);
                         }
                     }
                 },
                 
                 OpCode::Neg => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let res = match vb {
                         Value::Number(n) => Value::Number(-n),
                         Value::Complex(idx) => {
                             let c = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                             let neg = -c;
                             Value::Complex(self.heap.alloc_complex(neg))
                         }
                         _ => return Err(RuntimeError::TypeMismatch("Neg".into())),
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::Sqrt => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let res = match vb {
                         Value::Number(n) => {
                             if n < 0.0 {
                                 let c = Complex64::new(0.0, (-n).sqrt());
                                 Value::Complex(self.heap.alloc_complex(c))
                             } else {
                                 Value::Number(n.sqrt())
                             }
                         }
                         Value::Complex(idx) => {
                             let c = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                             let sqrt_c = c.sqrt();
                             Value::Complex(self.heap.alloc_complex(sqrt_c))
                         }
                         _ => return Err(RuntimeError::TypeMismatch("Sqrt".into())),
                     };
                     self.set_reg(base, a, res);
                 },
                 
                 OpCode::NewComplex => {
                     let a = decode_a(instruction) as usize;
                     let b = decode_b(instruction) as usize;
                     let c = decode_c(instruction) as usize;
                     let vb = self.get_reg(base, b);
                     let vc = self.get_reg(base, c);
                     
                     let re = match vb {
                         Value::Number(n) => n,
                         _ => return Err(RuntimeError::TypeMismatch("NewComplex: real part must be Number".into())),
                     };
                     let im = match vc {
                         Value::Number(n) => n,
                         _ => return Err(RuntimeError::TypeMismatch("NewComplex: imag part must be Number".into())),
                     };
                     
                     let c = Complex64::new(re, im);
                     let res = Value::Complex(self.heap.alloc_complex(c));
                     self.set_reg(base, a, res);
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
                     
                     // Resolve Name from Constant Pool (Value::String owns the string now)
                     let name_val = func.constants.get(bx).cloned().unwrap_or(Value::Nil);
                     let name = if let Value::String(s) = name_val {
                          s
                     } else {
                          return Err(RuntimeError::TypeMismatch("Global name must be a string".into()));
                     };
                     
                     let mutable = op == OpCode::DefGlobalVar;
                     self.globals.insert(name, GlobalEntry { value: val, mutable });
                 },
                 
                 OpCode::GetGlobal => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     
                     // Resolve Name
                     let name_val = func.constants.get(bx).cloned().unwrap_or(Value::Nil);
                     let name = if let Value::String(s) = name_val {
                          s
                     } else {
                          return Err(RuntimeError::TypeMismatch("Global name must be a string".into()));
                     };
                     
                     if let Some(entry) = self.globals.get(&name) {
                         self.set_reg(base, a, entry.value.clone());
                     } else {
                         return Err(RuntimeError::Unknown(format!("Undefined global variable: {}", name)));
                     }
                 },
                 
                 OpCode::SetGlobal => {
                     let a = decode_a(instruction) as usize;
                     let bx = decode_bx(instruction) as usize;
                     let val = self.get_reg(base, a);
                     
                     // Resolve Name
                     let name_val = func.constants.get(bx).cloned().unwrap_or(Value::Nil);
                     let name = if let Value::String(s) = name_val {
                          s
                     } else {
                          return Err(RuntimeError::TypeMismatch("Global name must be a string".into()));
                     };
                     
                     if let Some(entry) = self.globals.get_mut(&name) {
                         if entry.mutable {
                             entry.value = val;
                         } else {
                             return Err(RuntimeError::Unknown(format!("Cannot assign to immutable global '{}'", name)));
                         }
                     } else {
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
        match (left, right) {
            // Direct f64 arithmetic for IEEE754 compliance (NaN, Infinity)
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(f64_op(a, b)))
            }
            (Value::Number(a), Value::Complex(idx)) => {
                let cb = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                let ca = Complex64::new(a, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::Number(result.re))
                } else {
                    Ok(Value::Complex(self.heap.alloc_complex(result)))
                }
            }
            (Value::Complex(idx), Value::Number(b)) => {
                let ca = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                let cb = Complex64::new(b, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::Number(result.re))
                } else {
                    Ok(Value::Complex(self.heap.alloc_complex(result)))
                }
            }
            (Value::Complex(idx_a), Value::Complex(idx_b)) => {
                let ca = self.heap.get_complex(idx_a).ok_or(RuntimeError::InvalidOperand)?;
                let cb = self.heap.get_complex(idx_b).ok_or(RuntimeError::InvalidOperand)?;
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::Number(result.re))
                } else {
                    Ok(Value::Complex(self.heap.alloc_complex(result)))
                }
            }
            _ => Err(RuntimeError::TypeMismatch("Operands must be numeric".into())),
        }
    }
    
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
