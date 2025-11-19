//! Control flow instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::vm::ops::ValueOperations;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute control flow instructions
    pub(crate) fn execute_control(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);

        match opcode {
            OpCode::Jump => {
                let offset = decode_sbx(instruction);
                self.current_frame_mut()?.jump(offset);
                Ok(ExecutionResult::Continue)
            }

            OpCode::JumpIfTrue => {
                let cond = self.get_register(a)?;
                if ValueOperations::is_truthy(cond) {
                    let offset = decode_sbx(instruction);
                    self.current_frame_mut()?.jump(offset);
                }
                Ok(ExecutionResult::Continue)
            }

            OpCode::JumpIfFalse => {
                let cond = self.get_register(a)?;
                if !ValueOperations::is_truthy(cond) {
                    let offset = decode_sbx(instruction);
                    self.current_frame_mut()?.jump(offset);
                }
                Ok(ExecutionResult::Continue)
            }

            OpCode::Return => {
                let value = self.get_register(a)?.clone();
                Ok(ExecutionResult::Return(value))
            }

            OpCode::ReturnNull => Ok(ExecutionResult::Return(crate::value::Value::Null)),

            _ => unreachable!("Non-control opcode in control handler"),
        }
    }
}
