use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::stack::StackOps;
use super::value_ops::ValueOps;

/// Trait for comparison instruction handlers (Lt, Gt, Le, Ge, Eq, NotEq, LogNot)
pub trait ComparisonOps {
    fn handle_comparison(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError>;
}

impl ComparisonOps for super::vm::VM {
    fn handle_comparison(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError> {
        match op {
            OpCode::Eq => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let v1 = self.get_reg(base, b)?;
                let v2 = self.get_reg(base, c)?;
                self.set_reg(base, a, Value::bool(self.values_equal(v1, v2)))?;
            }

            OpCode::NotEq => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let v1 = self.get_reg(base, b)?;
                let v2 = self.get_reg(base, c)?;
                self.set_reg(base, a, Value::bool(!self.values_equal(v1, v2)))?;
            }

            OpCode::Lt | OpCode::Gt | OpCode::Le | OpCode::Ge => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let v1 = self.get_reg(base, b)?;
                let v2 = self.get_reg(base, c)?;

                let result = self.compare_values(op, v1, v2)?;
                self.set_reg(base, a, Value::bool(result))?;
            }

            OpCode::LogNot => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let val = self.get_reg(base, b)?;
                self.set_reg(base, a, Value::bool(val.is_falsey()))?;
            }

            // ===== Specialized integer comparisons (no type check) =====
            OpCode::GtInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                debug_assert!(self.get_reg(base, b)?.is_int(), "GtInt lhs non-int");
                debug_assert!(self.get_reg(base, c)?.is_int(), "GtInt rhs non-int");
                let n1 = unsafe { self.get_reg(base, b)?.as_int_unchecked() };
                let n2 = unsafe { self.get_reg(base, c)?.as_int_unchecked() };
                self.set_reg(base, a, Value::bool(n1 > n2))?;
            }

            OpCode::LtInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let n1 = unsafe { self.get_reg(base, b)?.as_int_unchecked() };
                let n2 = unsafe { self.get_reg(base, c)?.as_int_unchecked() };
                self.set_reg(base, a, Value::bool(n1 < n2))?;
            }

            OpCode::GeInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let n1 = unsafe { self.get_reg(base, b)?.as_int_unchecked() };
                let n2 = unsafe { self.get_reg(base, c)?.as_int_unchecked() };
                self.set_reg(base, a, Value::bool(n1 >= n2))?;
            }

            OpCode::LeInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let n1 = unsafe { self.get_reg(base, b)?.as_int_unchecked() };
                let n2 = unsafe { self.get_reg(base, c)?.as_int_unchecked() };
                self.set_reg(base, a, Value::bool(n1 <= n2))?;
            }

            OpCode::EqInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                // Int values are inline — raw u64 equality suffices.
                let v1 = self.get_reg(base, b)?;
                let v2 = self.get_reg(base, c)?;
                self.set_reg(base, a, Value::bool(v1 == v2))?;
            }

            OpCode::NeqInt => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;
                let v1 = self.get_reg(base, b)?;
                let v2 = self.get_reg(base, c)?;
                self.set_reg(base, a, Value::bool(v1 != v2))?;
            }

            _ => return Err(RuntimeError::InvalidOpcode(op as u8)),
        }

        Ok(())
    }
}

impl super::vm::VM {
    /// Compare two values with the given ordering operator.
    fn compare_values(&self, op: OpCode, v1: Value, v2: Value) -> Result<bool, RuntimeError> {
        if v1.is_int() && v2.is_int() {
            // SAFETY: is_int() verified above for both operands.
            let n1 = unsafe { v1.as_int_unchecked() };
            let n2 = unsafe { v2.as_int_unchecked() };
            return Ok(match op {
                OpCode::Lt => n1 < n2,
                OpCode::Gt => n1 > n2,
                OpCode::Le => n1 <= n2,
                OpCode::Ge => n1 >= n2,
                _ => unreachable!(),
            });
        }

        if v1.is_field() && v2.is_field() {
            let h1 = v1
                .as_handle()
                .ok_or_else(|| RuntimeError::type_mismatch("bad field handle"))?;
            let h2 = v2
                .as_handle()
                .ok_or_else(|| RuntimeError::type_mismatch("bad field handle"))?;
            let f1 = self
                .heap
                .get_field(h1)
                .ok_or(RuntimeError::stale_heap("Field", "comparison"))?;
            let f2 = self
                .heap
                .get_field(h2)
                .ok_or(RuntimeError::stale_heap("Field", "comparison"))?;
            let (c1, c2) = (f1.to_canonical(), f2.to_canonical());
            return Ok(match op {
                OpCode::Lt => c1 < c2,
                OpCode::Gt => c1 > c2,
                OpCode::Le => c1 <= c2,
                OpCode::Ge => c1 >= c2,
                _ => unreachable!(),
            });
        }

        if v1.is_bigint() && v2.is_bigint() {
            let h1 = v1.as_handle().ok_or(RuntimeError::InvalidOperand)?;
            let h2 = v2.as_handle().ok_or(RuntimeError::InvalidOperand)?;
            let b1 = self
                .heap
                .get_bigint(h1)
                .ok_or(RuntimeError::InvalidOperand)?;
            let b2 = self
                .heap
                .get_bigint(h2)
                .ok_or(RuntimeError::InvalidOperand)?;
            return Ok(match op {
                OpCode::Lt => b1 < b2,
                OpCode::Gt => b1 > b2,
                OpCode::Le => b1 <= b2,
                OpCode::Ge => b1 >= b2,
                _ => unreachable!(),
            });
        }

        let op_str = match op {
            OpCode::Lt => "<",
            OpCode::Gt => ">",
            OpCode::Le => "<=",
            OpCode::Ge => ">=",
            _ => "?",
        };
        Err(RuntimeError::type_mismatch(format!(
            "Expected numeric values for {op_str} comparison"
        )))
    }
}
