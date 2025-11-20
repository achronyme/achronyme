//! Arithmetic instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::vm::ops::ValueOperations;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute arithmetic instructions
    pub(crate) fn execute_arithmetic(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);

        match opcode {
            OpCode::Add => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::add_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Sub => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::sub_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Mul => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::mul_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Div => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::div_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Pow => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::pow_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Neg => {
                let value = self.get_register(b)?;
                let result = ValueOperations::neg_value(value)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Not => {
                let value = self.get_register(b)?;
                let result = ValueOperations::not_value(value)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-arithmetic opcode in arithmetic handler"),
        }
    }
}
