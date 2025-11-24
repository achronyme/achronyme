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
                let record = Value::Record(std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::HashMap::new(),
                )));
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

                // 1. Attempt to get field from Record
                if let Value::Record(rec_rc) = &rec_value {
                    let rec_borrowed = rec_rc.borrow();
                    if let Some(val) = rec_borrowed.get(field_name) {
                        self.set_register(dst, val.clone())?;
                        return Ok(ExecutionResult::Continue);
                    }
                    // Field not found in Record map, proceed to check intrinsics
                }

                // 2. Attempt to find intrinsic method
                if let Some(type_disc) =
                    crate::vm::intrinsics::TypeDiscriminant::from_value(&rec_value)
                {
                    if let Some(func) = self.intrinsics.lookup(&type_disc, field_name) {
                        // Special case for Signal.value (getter)
                        // We invoke it immediately instead of returning a BoundMethod
                        if matches!(type_disc, crate::vm::intrinsics::TypeDiscriminant::Signal)
                            && field_name == "value"
                        {
                            // Invoke intrinsic with just the receiver
                            // Note: IntrinsicFn signature is (vm, receiver, args)
                            let result = func(self, &rec_value, &[])?;
                            self.set_register(dst, result)?;
                            return Ok(ExecutionResult::Continue);
                        }

                        // Found an intrinsic method!
                        let bound_method = Value::BoundMethod {
                            receiver: Box::new(rec_value.clone()),
                            method_name: field_name.to_string(),
                        };
                        self.set_register(dst, bound_method)?;
                        return Ok(ExecutionResult::Continue);
                    }
                }

                // 3. Special case for Error fields
                if let Value::Error {
                    message,
                    kind,
                    source,
                } = &rec_value
                {
                    let value = match field_name {
                        "message" => Value::String(message.clone()),
                        "kind" => match kind {
                            Some(k) => Value::String(k.clone()),
                            None => Value::Null,
                        },
                        "source" => match source {
                            Some(s) => (**s).clone(),
                            None => Value::Null,
                        },
                        _ => {
                            return Err(VmError::Runtime(format!(
                                "Field '{}' not found in Error",
                                field_name
                            )))
                        }
                    };
                    self.set_register(dst, value)?;
                    return Ok(ExecutionResult::Continue);
                }

                // 4. Field not found
                if let Value::Record(_) = rec_value {
                    Err(VmError::Runtime(format!(
                        "Field '{}' not found in record",
                        field_name
                    )))
                } else {
                    Err(VmError::TypeError {
                        operation: "record field access".to_string(),
                        expected: "Record or Object with method".to_string(),
                        got: format!("{:?}", rec_value),
                    })
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
