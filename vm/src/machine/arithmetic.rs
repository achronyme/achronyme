use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::{FieldElement, Value, I60_MAX, I60_MIN};

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
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_string() || vc.is_string() {
                    let sb = self.val_to_string(&vb);
                    let sc = self.val_to_string(&vc);
                    let handle = self.heap.alloc_string(sb + &sc);
                    self.set_reg(base, a, Value::string(handle))?;
                } else if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    match ib.checked_add(ic) {
                        Some(result) if (I60_MIN..=I60_MAX).contains(&result) => {
                            self.set_reg(base, a, Value::int(result))?;
                        }
                        _ => {
                            // Overflow -> promote to Field
                            let fa = FieldElement::from_i64(ib);
                            let fb = FieldElement::from_i64(ic);
                            let result = fa.add(&fb);
                            let handle = self.heap.alloc_field(result);
                            self.set_reg(base, a, Value::field(handle))?;
                        }
                    }
                } else {
                    let res =
                        self.binary_op(vb, vc, |a: &FieldElement, b: &FieldElement| Ok(a.add(b)))?;
                    self.set_reg(base, a, res)?;
                }
            }

            OpCode::Sub => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    match ib.checked_sub(ic) {
                        Some(result) if (I60_MIN..=I60_MAX).contains(&result) => {
                            self.set_reg(base, a, Value::int(result))?;
                        }
                        _ => {
                            let fa = FieldElement::from_i64(ib);
                            let fb = FieldElement::from_i64(ic);
                            let result = fa.sub(&fb);
                            let handle = self.heap.alloc_field(result);
                            self.set_reg(base, a, Value::field(handle))?;
                        }
                    }
                } else {
                    let res =
                        self.binary_op(vb, vc, |a: &FieldElement, b: &FieldElement| Ok(a.sub(b)))?;
                    self.set_reg(base, a, res)?;
                }
            }

            OpCode::Mul => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                let vc = self.get_reg(base, c)?;

                if vb.is_int() && vc.is_int() {
                    let ib = vb.as_int().unwrap();
                    let ic = vc.as_int().unwrap();
                    match ib.checked_mul(ic) {
                        Some(result) if (I60_MIN..=I60_MAX).contains(&result) => {
                            self.set_reg(base, a, Value::int(result))?;
                        }
                        _ => {
                            let fa = FieldElement::from_i64(ib);
                            let fb = FieldElement::from_i64(ic);
                            let result = fa.mul(&fb);
                            let handle = self.heap.alloc_field(result);
                            self.set_reg(base, a, Value::field(handle))?;
                        }
                    }
                } else {
                    let res =
                        self.binary_op(vb, vc, |a: &FieldElement, b: &FieldElement| Ok(a.mul(b)))?;
                    self.set_reg(base, a, res)?;
                }
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
                    self.set_reg(base, a, Value::int(ib / ic))?;
                } else {
                    let res = self.binary_op(vb, vc, |a: &FieldElement, b: &FieldElement| {
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
                    self.set_reg(base, a, Value::int(ib % ic))?;
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "Modulo requires integer operands".into(),
                    ));
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
                        // Negative exponent -> promote to field, use field inverse
                        let fa = FieldElement::from_i64(base_val);
                        let inv = fa.inv().ok_or(RuntimeError::DivisionByZero)?;
                        let result = inv.pow(&[(-exp_val) as u64, 0, 0, 0]);
                        let handle = self.heap.alloc_field(result);
                        self.set_reg(base, a, Value::field(handle))?;
                    } else if exp_val == 0 {
                        self.set_reg(base, a, Value::int(1))?;
                    } else {
                        // Integer pow with overflow check
                        let mut result: i64 = 1;
                        let mut overflowed = false;
                        for _ in 0..exp_val {
                            match result.checked_mul(base_val) {
                                Some(r) if (I60_MIN..=I60_MAX).contains(&r) => result = r,
                                _ => {
                                    overflowed = true;
                                    break;
                                }
                            }
                        }
                        if overflowed {
                            let fa = FieldElement::from_i64(base_val);
                            let result = fa.pow(&[exp_val as u64, 0, 0, 0]);
                            let handle = self.heap.alloc_field(result);
                            self.set_reg(base, a, Value::field(handle))?;
                        } else {
                            self.set_reg(base, a, Value::int(result))?;
                        }
                    }
                } else if vb.is_field() && vc.is_int() {
                    let ha = vb
                        .as_handle()
                        .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                    let fa = *self
                        .heap
                        .get_field(ha)
                        .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                    let exp_val = vc.as_int().unwrap();
                    if exp_val < 0 {
                        let inv = fa.inv().ok_or(RuntimeError::DivisionByZero)?;
                        let result = inv.pow(&[(-exp_val) as u64, 0, 0, 0]);
                        let handle = self.heap.alloc_field(result);
                        self.set_reg(base, a, Value::field(handle))?;
                    } else {
                        let exp = [exp_val as u64, 0, 0, 0];
                        let result = fa.pow(&exp);
                        let handle = self.heap.alloc_field(result);
                        self.set_reg(base, a, Value::field(handle))?;
                    }
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "Pow requires numeric operands".into(),
                    ));
                }
            }

            OpCode::Neg => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let vb = self.get_reg(base, b)?;
                if vb.is_int() {
                    let ib = vb.as_int().unwrap();
                    // Handle i60 overflow: negating I60_MIN overflows
                    match ib.checked_neg() {
                        Some(result) if (I60_MIN..=I60_MAX).contains(&result) => {
                            self.set_reg(base, a, Value::int(result))?;
                        }
                        _ => {
                            let fa = FieldElement::from_i64(ib);
                            let result = fa.neg();
                            let handle = self.heap.alloc_field(result);
                            self.set_reg(base, a, Value::field(handle))?;
                        }
                    }
                } else if vb.is_field() {
                    let h = vb
                        .as_handle()
                        .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                    let fe = *self
                        .heap
                        .get_field(h)
                        .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                    let result = fe.neg();
                    let handle = self.heap.alloc_field(result);
                    self.set_reg(base, a, Value::field(handle))?;
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "Neg requires numeric operand".into(),
                    ));
                }
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
