//! Exception handling instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
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
                let value = self.get_register(a)?.clone();

                // Convert the thrown value to a proper Error value
                let error_value = match value {
                    // If it's already an Error, use it as-is
                    Value::Error { .. } => value,

                    // If it's a String, wrap it in an Error with message
                    Value::String(s) => Value::Error {
                        message: s,
                        kind: None,
                        source: None,
                    },

                    // If it's a Record with message/kind fields, convert to Error
                    Value::Record(fields) => {
                        let fields_ref = fields.borrow();

                        // Extract message (required)
                        let message = if let Some(msg_val) = fields_ref.get("message") {
                            match msg_val {
                                Value::String(s) => s.clone(),
                                _ => format!("{:?}", msg_val),
                            }
                        } else {
                            format!("{:?}", Value::Record(fields.clone()))
                        };

                        // Extract kind (optional)
                        let kind = fields_ref.get("kind").and_then(|k| {
                            match k {
                                Value::String(s) => Some(s.clone()),
                                _ => None,
                            }
                        });

                        // Extract source (optional)
                        let source = fields_ref.get("source").map(|s| Box::new(s.clone()));

                        Value::Error {
                            message,
                            kind,
                            source,
                        }
                    }

                    // For any other value, convert to string and wrap in Error
                    other => Value::Error {
                        message: format!("{:?}", other),
                        kind: None,
                        source: None,
                    },
                };

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
