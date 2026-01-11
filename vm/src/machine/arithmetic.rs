use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;
use num_complex::Complex64;

use super::promotion::TypePromotion;
use super::stack::StackOps;

/// Trait for arithmetic instruction handlers
pub trait ArithmeticOps {
    fn handle_arithmetic(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError>;
}

impl ArithmeticOps for super::vm::VM {
    fn handle_arithmetic(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError> {
        match op {
            OpCode::Add => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);
                
                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    self.set_reg(base, a, Value::int(ib.wrapping_add(ic)));
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x + y, |x, y| x + y)?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Sub => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    self.set_reg(base, a, Value::int(ib.wrapping_sub(ic)));
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x - y, |x, y| x - y)?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Mul => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    self.set_reg(base, a, Value::int(ib.wrapping_mul(ic)));
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x * y, |x, y| x * y)?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Div => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    if ic == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.set_reg(base, a, Value::int(ib.wrapping_div(ic)));
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x / y, |x, y| x / y)?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Mod => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    if ic == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.set_reg(base, a, Value::int(ib.wrapping_rem(ic)));
                } else {
                    let val_b = if let Some(i) = vb.as_int() {
                        i as f64
                    } else if let Some(n) = vb.as_number() {
                        n
                    } else {
                        return Err(RuntimeError::TypeMismatch("Mod operands must be numeric".into()));
                    };

                    let val_c = if let Some(i) = vc.as_int() {
                        i as f64
                    } else if let Some(n) = vc.as_number() {
                        n
                    } else {
                        return Err(RuntimeError::TypeMismatch("Mod operands must be numeric".into()));
                    };

                    self.set_reg(base, a, Value::number(val_b % val_c));
                }
            }

            OpCode::Pow => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                if vb.is_int() && vc.is_int() {
                    let base_val = vb.as_int().unwrap();
                    let exp_val = vc.as_int().unwrap();
                    
                    if exp_val < 0 {
                         let res = (base_val as f64).powf(exp_val as f64);
                         self.set_reg(base, a, Value::number(res));
                    } else {
                        let res = base_val.wrapping_pow(exp_val as u32);
                        self.set_reg(base, a, Value::int(res));
                    }
                } else if vb.is_number() && vc.is_number() {
                    let x = vb.as_number().unwrap();
                    let y = vc.as_number().unwrap();

                    let res_real = x.powf(y);
                    if res_real.is_nan() && x < 0.0 {
                        // Promotion case: (-4)^0.5 = 2i
                        let cx = Complex64::new(x, 0.0);
                        let cy = Complex64::new(y, 0.0);
                        let res_complex = cx.powc(cy);
                        let res = Value::complex(self.heap.alloc_complex(res_complex));
                        self.set_reg(base, a, res);
                    } else {
                        self.set_reg(base, a, Value::number(res_real));
                    }
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x.powf(y), |x, y| x.powc(y))?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Neg => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b);
                let res = if vb.is_int() {
                     Value::int(vb.as_int().unwrap().wrapping_neg())
                } else if vb.is_number() {
                    Value::number(-vb.as_number().unwrap())
                } else if vb.is_complex() {
                    let idx = vb.as_handle().unwrap();
                    let c = self
                        .heap
                        .get_complex(idx)
                        .ok_or(RuntimeError::InvalidOperand)?;
                    let neg = -c;
                    Value::complex(self.heap.alloc_complex(neg))
                } else {
                    return Err(RuntimeError::TypeMismatch("Neg".into()));
                };
                self.set_reg(base, a, res);
            }

            OpCode::Sqrt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b);
                
                // Int -> Float/Complex promotion
                let (val, need_complex) = if vb.is_int() {
                    let i = vb.as_int().unwrap();
                    (i as f64, i < 0)
                } else if vb.is_number() {
                    let n = vb.as_number().unwrap();
                    (n, n < 0.0)
                } else if vb.is_complex() {
                    // Already handled logic, duplicate slightly but distinct type
                     let idx = vb.as_handle().unwrap();
                     let c = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
                     let sqrt_c = c.sqrt();
                     let res = Value::complex(self.heap.alloc_complex(sqrt_c));
                     self.set_reg(base, a, res);
                     return Ok(());
                } else {
                     return Err(RuntimeError::TypeMismatch("Sqrt".into()));
                };

                // Common Float/Int Logic
                let res = if need_complex {
                    let c = Complex64::new(0.0, (-val).sqrt());
                    Value::complex(self.heap.alloc_complex(c))
                } else {
                    Value::number(val.sqrt())
                };
                self.set_reg(base, a, res);
            }

            OpCode::NewComplex => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                let re = if vb.is_int() {
                    vb.as_int().unwrap() as f64
                } else if vb.is_number() {
                    vb.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "NewComplex: real part must be Number/Int".into(),
                    ));
                };
                
                let im = if vc.is_int() {
                    vc.as_int().unwrap() as f64
                } else if vc.is_number() {
                    vc.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "NewComplex: imag part must be Number/Int".into(),
                    ));
                };

                let c = Complex64::new(re, im);
                let res = Value::complex(self.heap.alloc_complex(c));
                self.set_reg(base, a, res);
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
