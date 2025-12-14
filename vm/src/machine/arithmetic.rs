use crate::opcode::{OpCode, instruction::*};
use crate::error::RuntimeError;
use memory::Value;
use num_complex::Complex64;

use super::stack::StackOps;
use super::promotion::TypePromotion;

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
                let res = self.binary_op(vb, vc, |x, y| x + y, |x, y| x + y)?;
                self.set_reg(base, a, res);
            }

            OpCode::Sub => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);
                let res = self.binary_op(vb, vc, |x, y| x - y, |x, y| x - y)?;
                self.set_reg(base, a, res);
            }

            OpCode::Mul => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);
                let res = self.binary_op(vb, vc, |x, y| x * y, |x, y| x * y)?;
                self.set_reg(base, a, res);
            }

            OpCode::Div => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);
                let res = self.binary_op(vb, vc, |x, y| x / y, |x, y| x / y)?;
                self.set_reg(base, a, res);
            }

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
            }

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
            }

            OpCode::NewComplex => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b);
                let vc = self.get_reg(base, c);

                let re = if vb.is_number() {
                    vb.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "NewComplex: real part must be Number".into(),
                    ));
                };
                let im = if vc.is_number() {
                    vc.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "NewComplex: imag part must be Number".into(),
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
