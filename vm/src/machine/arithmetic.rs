use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::{FieldElement, Value};

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
/// - $field_op: The closure for field element operations
macro_rules! binary_arithmetic_op {
    ($self:ident, $instruction:ident, $base:ident, $int_op:ident, $float_op:expr, $field_op:expr) => {{
        let a = decode_a($instruction) as usize;
        let b = decode_b($instruction) as usize;
        let c = decode_c($instruction) as usize;
        let vb = $self.get_reg($base, b)?;
        let vc = $self.get_reg($base, c)?;

        if vb.is_int() && vc.is_int() {
            let ib = vb.as_int().unwrap();
            let ic = vc.as_int().unwrap();
            $self.set_reg($base, a, Value::int(ib.$int_op(ic)))?;
        } else {
            let res = $self.binary_op(vb, vc, |x, y| $float_op(x, y), $field_op)?;
            $self.set_reg($base, a, res)?;
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
                binary_arithmetic_op!(self, instruction, base, wrapping_add,
                    |x, y| x + y,
                    |a: &FieldElement, b: &FieldElement| Ok(a.add(b)));
            }

            OpCode::Sub => {
                binary_arithmetic_op!(self, instruction, base, wrapping_sub,
                    |x, y| x - y,
                    |a: &FieldElement, b: &FieldElement| Ok(a.sub(b)));
            }

            OpCode::Mul => {
                binary_arithmetic_op!(self, instruction, base, wrapping_mul,
                    |x, y| x * y,
                    |a: &FieldElement, b: &FieldElement| Ok(a.mul(b)));
            }

            OpCode::Div => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    if ic == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.set_reg(base, a, Value::int(ib.wrapping_div(ic)))?;
                } else {
                    let res = self.binary_op(vb, vc,
                        |x, y| x / y,
                        |a: &FieldElement, b: &FieldElement| {
                            a.div(b).ok_or(RuntimeError::DivisionByZero)
                        })?;
                    self.set_reg(base, a, res)?;
                }
            }

            OpCode::Mod => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    if ic == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.set_reg(base, a, Value::int(ib.wrapping_rem(ic)))?;
                } else if vb.is_field() || vc.is_field() {
                    return Err(RuntimeError::TypeMismatch(
                        "Modulo not defined for Field elements".into(),
                    ));
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

                    self.set_reg(base, a, Value::number(val_b % val_c))?;
                }
            }

            OpCode::Pow => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_int() && vc.is_int() {
                    let base_val = vb.as_int().unwrap();
                    let exp_val = vc.as_int().unwrap();

                    if exp_val < 0 {
                        let res = (base_val as f64).powf(exp_val as f64);
                        self.set_reg(base, a, Value::number(res))?;
                    } else {
                        let res = base_val.wrapping_pow(exp_val as u32);
                        self.set_reg(base, a, Value::int(res))?;
                    }
                } else if vb.is_field() && vc.is_int() {
                    // Field ^ Int: exponentiation in the field
                    let ha = vb.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                    let fa = *self.heap.get_field(ha).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                    let exp_val = vc.as_int().unwrap();
                    let exp = if exp_val >= 0 {
                        [exp_val as u64, 0, 0, 0]
                    } else {
                        // Negative exp: compute inverse first, then pow with |exp|
                        let inv = fa.inv().ok_or(RuntimeError::DivisionByZero)?;
                        let result = inv.pow(&[(-exp_val) as u64, 0, 0, 0]);
                        let handle = self.heap.alloc_field(result);
                        self.set_reg(base, a, Value::field(handle))?;
                        return Ok(());
                    };
                    let result = fa.pow(&exp);
                    let handle = self.heap.alloc_field(result);
                    self.set_reg(base, a, Value::field(handle))?;
                } else {
                    let res = self.binary_op(vb, vc,
                        |x, y| x.powf(y),
                        |_, _| unreachable!())?;
                    self.set_reg(base, a, res)?;
                }
            }

            OpCode::Neg => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                if vb.is_int() {
                    self.set_reg(base, a, Value::int(vb.as_int().unwrap().wrapping_neg()))?;
                } else if vb.is_number() {
                    self.set_reg(base, a, Value::number(-vb.as_number().unwrap()))?;
                } else if vb.is_field() {
                    let h = vb.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                    let fe = *self.heap.get_field(h).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                    let result = fe.neg();
                    let handle = self.heap.alloc_field(result);
                    self.set_reg(base, a, Value::field(handle))?;
                } else {
                    return Err(RuntimeError::TypeMismatch("Neg requires numeric operand".into()));
                }
            }

            OpCode::Sqrt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b)?;

                if vb.is_field() {
                    return Err(RuntimeError::TypeMismatch("Sqrt not defined for Field elements".into()));
                }

                let val = if vb.is_int() {
                    vb.as_int().unwrap() as f64
                } else if vb.is_number() {
                    vb.as_number().unwrap()
                } else {
                    return Err(RuntimeError::TypeMismatch("Sqrt requires numeric operand".into()));
                };

                self.set_reg(base, a, Value::number(val.sqrt()))?;
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
