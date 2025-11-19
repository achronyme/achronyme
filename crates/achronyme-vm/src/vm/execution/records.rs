//! Record instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute record instructions
    pub(crate) fn execute_records(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);

        match opcode {
            OpCode::NewRecord => {
                // R[A] = {} (new empty record)
                let dst = a;
                let record = Value::Record(std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new())));
                self.set_register(dst, record)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::GetField => {
                // R[A] = R[B][K[C]]
                let dst = a;
                let rec_reg = b;
                let key_idx = c as usize;

                let rec_value = self.get_register(rec_reg)?.clone();
                let field_name = self.get_string(key_idx)?;

                match &rec_value {
                    Value::Record(rec_rc) => {
                        let rec_borrowed = rec_rc.borrow();
                        let value = rec_borrowed
                            .get(field_name)
                            .ok_or_else(|| {
                                VmError::Runtime(format!("Field '{}' not found in record", field_name))
                            })?
                            .clone();
                        drop(rec_borrowed); // Explicitly drop the borrow
                        self.set_register(dst, value)?;
                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "record field access".to_string(),
                        expected: "Record".to_string(),
                        got: format!("{:?}", rec_value),
                    }),
                }
            }

            OpCode::SetField => {
                // R[A][K[B]] = R[C]
                let rec_reg = a;
                let key_idx = b as usize;
                let val_reg = c;

                let rec_value = self.get_register(rec_reg)?.clone();
                let field_name = self.get_string(key_idx)?;
                let new_value = self.get_register(val_reg)?.clone();

                match &rec_value {
                    Value::Record(rec_rc) => {
                        let mut rec_borrowed = rec_rc.borrow_mut();
                        rec_borrowed.insert(field_name.to_string(), new_value);
                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "record field assignment".to_string(),
                        expected: "Record".to_string(),
                        got: format!("{:?}", rec_value),
                    }),
                }
            }

            _ => unreachable!("Non-record opcode in record handler"),
        }
    }
}
