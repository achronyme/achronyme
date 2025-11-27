//! Variable and constant instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute variable operations
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
                let value = self.get_constant(bx as usize)?;
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
                let value = self.get_register(b)?;
                self.set_register(a, value)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::GetUpvalue => {
                let dst = a;
                let upvalue_idx = b as usize;

                let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;

                let upvalue = frame
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                let value = upvalue.read().clone();

                self.set_register(dst, value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::SetUpvalue => {
                let upvalue_idx = a as usize;
                let src = b;

                let value = self.get_register(src)?;

                let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;

                let upvalue = frame
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                *upvalue.write() = value;

                Ok(ExecutionResult::Continue)
            }

            OpCode::GetGlobal => {
                let dst = a;
                // Bx is index into constants pool for the name string
                let name_idx = bx as usize;
                let name = self.get_string(name_idx)?;

                let value_opt = self.globals.read().get(&name).cloned();
                if let Some(value) = value_opt {
                    self.set_register(dst, value)?;
                } else {
                    return Err(VmError::Runtime(format!(
                        "Undefined global variable: '{}'",
                        name
                    )));
                }

                Ok(ExecutionResult::Continue)
            }

            OpCode::SetGlobal => {
                let src = a;
                // Bx is index into constants pool for the name string
                let name_idx = bx as usize;
                let name = self.get_string(name_idx)?;
                let value = self.get_register(src)?;

                self.globals.write().insert(name, value);

                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-variable opcode in variable handler"),
        }
    }
}
