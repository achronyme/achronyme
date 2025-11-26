//! Pattern matching instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute pattern matching instructions
    pub(crate) fn execute_matching(
        &self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);

        match opcode {
            OpCode::MatchType => {
                // R[A] = typeof(R[B]) == K[C]
                // Matches the type of value in R[B] against type name in constant K[C]
                let dst = a;
                let value_reg = b;
                let type_idx = c as usize;

                let value = self.get_register(value_reg)?;
                let expected_type = self.get_string(type_idx)?;

                let matches = self.check_type_match(&value, &expected_type);
                self.set_register(dst, Value::Boolean(matches))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::MatchLit => {
                // R[A] = R[B] == K[C]
                // Matches value in R[B] against literal constant K[C]
                let dst = a;
                let value_reg = b;
                let const_idx = c as usize;

                let value = self.get_register(value_reg)?.clone();
                let literal = self.get_constant(const_idx)?.clone();

                let matches = value == literal;
                self.set_register(dst, Value::Boolean(matches))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::DestructureVec => {
                // Destructure R[B] to R[A].. using pattern descriptor in K[C]
                // Pattern descriptor contains: count of elements to extract
                // Elements are extracted to sequential registers starting at R[A]
                let dst_start = a;
                let vec_reg = b;
                let pattern_idx = c as usize;

                let vec_value = self.get_register(vec_reg)?.clone();

                match &vec_value {
                    Value::Vector(vec_rc) => {
                        // Get pattern descriptor (for now, just a number indicating element count)
                        let pattern_const = self.get_constant(pattern_idx)?;
                        let element_count = match pattern_const {
                            Value::Number(n) => n as usize,
                            _ => {
                                return Err(VmError::Runtime(
                                    "DestructureVec pattern descriptor must be a number"
                                        .to_string(),
                                ))
                            }
                        };

                        // Borrow the vector to extract elements
                        let vec_borrowed = vec_rc.read();

                        // Extract all values at once while we have the borrow
                        // If vector is too short, use null for missing elements (for default value support)
                        let mut values = Vec::new();
                        for i in 0..element_count {
                            let value = vec_borrowed.get(i).cloned().unwrap_or(Value::Null); // Use null if element doesn't exist
                            values.push(value);
                        }

                        // Drop the borrow before setting registers
                        drop(vec_borrowed);

                        // Now set the registers
                        for (i, value) in values.into_iter().enumerate() {
                            let target_reg = dst_start.checked_add(i as u8).ok_or(
                                VmError::Runtime("Register overflow in destructuring".to_string()),
                            )?;
                            self.set_register(target_reg, value)?;
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "vector destructuring".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::DestructureRec => {
                // Destructure R[B] to R[A].. using pattern descriptor in K[C]
                // Pattern descriptor is a vector of field names in the constant pool
                // Fields are extracted to sequential registers starting at R[A]
                let dst_start = a;
                let rec_reg = b;
                let pattern_idx = c as usize;

                let rec_value = self.get_register(rec_reg)?.clone();

                match &rec_value {
                    Value::Record(rec_rc) => {
                        // Get pattern descriptor (vector of field names)
                        let pattern_const = self.get_constant(pattern_idx)?;
                        let field_names = match pattern_const {
                            Value::Vector(fields_rc) => {
                                let fields_borrowed = fields_rc.read();
                                // Extract field names from vector
                                let mut names = Vec::new();
                                for field in fields_borrowed.iter() {
                                    match field {
                                        Value::String(s) => names.push(s.clone()),
                                        _ => {
                                            return Err(VmError::Runtime(
                                                "DestructureRec pattern must contain strings"
                                                    .to_string(),
                                            ))
                                        }
                                    }
                                }
                                names
                            }
                            _ => {
                                return Err(VmError::Runtime(
                                    "DestructureRec pattern descriptor must be a vector"
                                        .to_string(),
                                ))
                            }
                        };

                        // Extract all fields at once while we have the borrow
                        // If a field doesn't exist, use null (for default value support)
                        let rec_borrowed = rec_rc.read();
                        let mut values = Vec::new();
                        for field_name in field_names.iter() {
                            let value =
                                rec_borrowed.get(field_name).cloned().unwrap_or(Value::Null); // Use null if field doesn't exist
                            values.push(value);
                        }

                        // Drop the borrow before setting registers
                        drop(rec_borrowed);

                        // Now set the registers
                        for (i, value) in values.into_iter().enumerate() {
                            let target_reg = dst_start.checked_add(i as u8).ok_or(
                                VmError::Runtime("Register overflow in destructuring".to_string()),
                            )?;
                            self.set_register(target_reg, value)?;
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "record destructuring".to_string(),
                        expected: "Record".to_string(),
                        got: format!("{:?}", rec_value),
                    }),
                }
            }

            _ => unreachable!("Non-matching opcode in matching handler"),
        }
    }

    /// Check if a value matches a type name
    fn check_type_match(&self, value: &Value, type_name: &str) -> bool {
        matches!(
            (value, type_name),
            (Value::Number(_), "Number")
                | (Value::Boolean(_), "Boolean")
                | (Value::String(_), "String")
                | (Value::Null, "Null")
                | (Value::Vector(_), "Vector")
                | (Value::Vector(_), "Array")
                | (Value::Record(_), "Record")
                | (Value::Record(_), "Object")
                | (Value::Function(_), "Function")
                | (Value::Complex(_), "Complex")
                | (Value::Tensor(_), "Tensor")
                | (Value::ComplexTensor(_), "ComplexTensor")
                | (Value::Generator(_), "Generator")
                | (Value::Error { .. }, "Error")
                | (Value::MutableRef(_), "MutableRef")
                | (Value::Sender(_), "Sender")
                | (Value::Receiver(_), "Receiver")
                | (Value::AsyncMutex(_), "AsyncMutex")
                | (Value::MutexGuard(_), "MutexGuard")
                | (Value::Signal(_), "Signal")
        )
    }
}
