//! Comparison instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::ops::ValueOperations;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute comparison instructions
    pub(crate) fn execute_comparison(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);

        match opcode {
            OpCode::Eq => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = Value::Boolean(left == right);
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Lt => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::lt_values(&left, &right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Le => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::le_values(&left, &right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Gt => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::gt_values(&left, &right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Ge => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = ValueOperations::ge_values(&left, &right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Ne => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = Value::Boolean(left != right);
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-comparison opcode in comparison handler"),
        }
    }
}
