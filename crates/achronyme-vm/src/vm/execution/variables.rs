//! Variable and constant instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute variable and constant loading instructions
    pub(crate) fn execute_variables(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let bx = decode_bx(instruction);

        match opcode {
            OpCode::LoadConst => {
                let value = self.get_constant(bx as usize)?.clone();
                self.set_register(a, value)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadNull => {
                self.set_register(a, Value::Null)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadTrue => {
                self.set_register(a, Value::Boolean(true))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadFalse => {
                self.set_register(a, Value::Boolean(false))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadImmI8 => {
                self.set_register(a, Value::Number(bx as i16 as f64))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Move => {
                let value = self.get_register(b)?.clone();
                self.set_register(a, value)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::GetUpvalue => {
                let dst = a;
                let upvalue_idx = b as usize;

                let upvalue = self
                    .current_frame()?
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                let value = upvalue.borrow().clone();
                self.set_register(dst, value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::SetUpvalue => {
                let upvalue_idx = a as usize;
                let src = b;

                let value = self.get_register(src)?.clone();
                let upvalue = self
                    .current_frame()?
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                *upvalue.borrow_mut() = value;

                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-variable opcode in variable handler"),
        }
    }
}
