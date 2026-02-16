use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

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

/// Macro to handle binary arithmetic operations with type dispatch.
/// Arguments:
/// - $self: The VM instance
/// - $instruction: The raw instruction u32
/// - $base: The current stack base
/// - $int_op: The integer method to call (e.g., wrapping_add)
/// - $float_op: The closure for float operations
macro_rules! binary_arithmetic_op {
    ($self:ident, $instruction:ident, $base:ident, $int_op:ident, $float_op:expr) => {{
        let a = decode_a($instruction) as usize;
        let b = decode_b($instruction) as usize;
        let c = decode_c($instruction) as usize;
        // Direct unsafe access via get_reg is verified safe by bytecode validation
        let vb = $self.get_reg($base, b);
        let vc = $self.get_reg($base, c);

        if vb.is_int() && vc.is_int() {
            // Fast Path: SMI Arithmetics (No Heap Alloc, No Float logic)
            // SAFETY: unwrap() is safe because is_int() checked the tag.
            let ib = vb.as_int().unwrap();
            let ic = vc.as_int().unwrap();
            $self.set_reg($base, a, Value::int(ib.$int_op(ic)));
        } else {
            // Slow Path: Promotion / Float
            // We delegate to the unified binary_op helper which handles coercions.
            let res = $self.binary_op(vb, vc, |x, y| $float_op(x, y))?;
            $self.set_reg($base, a, res);
        }
    }};
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
                binary_arithmetic_op!(self, instruction, base, wrapping_add, |x, y| x + y);
            }

            OpCode::Sub => {
                binary_arithmetic_op!(self, instruction, base, wrapping_sub, |x, y| x - y);
            }

            OpCode::Mul => {
                binary_arithmetic_op!(self, instruction, base, wrapping_mul, |x, y| x * y);
            }

            OpCode::Div => {
                // Div has special check for zero in Int path
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
                    let res = self.binary_op(vb, vc, |x, y| x / y)?;
                    self.set_reg(base, a, res);
                }
            }

            OpCode::Mod => {
                // Mod has special check for zero AND special coercion rules
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
                        return Err(RuntimeError::TypeMismatch(
                            "Mod operands must be numeric".into(),
                        ));
                    };

                    let val_c = if let Some(i) = vc.as_int() {
                        i as f64
                    } else if let Some(n) = vc.as_number() {
                        n
                    } else {
                        return Err(RuntimeError::TypeMismatch(
                            "Mod operands must be numeric".into(),
                        ));
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
                } else {
                    let res = self.binary_op(vb, vc, |x, y| x.powf(y))?;
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
                } else {
                    return Err(RuntimeError::TypeMismatch("Neg requires numeric operand".into()));
                };
                self.set_reg(base, a, res);
            }

            OpCode::Sqrt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b);

                let val = if vb.is_int() {
                    vb.as_int().unwrap() as f64
                } else if vb.is_number() {
                    vb.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch("Sqrt requires numeric operand".into()));
                };

                // IEEE 754: sqrt of negative returns NaN
                self.set_reg(base, a, Value::number(val.sqrt()));
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
