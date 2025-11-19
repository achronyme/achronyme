//! Exception handling instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::vm::frame::ExceptionHandler;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute exception handling instructions
    pub(crate) fn execute_exceptions(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        match opcode {
            OpCode::Throw => {
                let a = decode_a(instruction);
                let error_value = self.get_register(a)?.clone();
                Ok(ExecutionResult::Exception(error_value))
            }

            OpCode::PushHandler => {
                let a = decode_a(instruction);
                let offset = decode_sbx(instruction);

                // Calculate absolute catch_ip: current IP + offset
                let frame = self.current_frame()?;
                let catch_ip = (frame.ip as isize + offset as isize) as usize;

                // Push handler to current frame
                let handler = ExceptionHandler {
                    catch_ip,
                    error_reg: a,
                };

                self.current_frame_mut()?.handlers.push(handler);
                Ok(ExecutionResult::Continue)
            }

            OpCode::PopHandler => {
                let frame = self.current_frame_mut()?;
                if frame.handlers.is_empty() {
                    return Err(VmError::Runtime("No exception handler to pop".to_string()));
                }
                frame.handlers.pop();
                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-exception opcode in exception handler"),
        }
    }
}
