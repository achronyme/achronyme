//! Vector instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute vector instructions
    pub(crate) fn execute_vectors(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);

        match opcode {
            OpCode::NewVector => {
                // R[A] = [] (new empty vector)
                let dst = a;
                let vector = Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(Vec::new())));
                self.set_register(dst, vector)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::VecPush => {
                // R[A].push(R[B])
                let vec_reg = a;
                let val_reg = b;

                let vec_value = self.get_register(vec_reg)?.clone();
                let push_value = self.get_register(val_reg)?.clone();

                match vec_value {
                    Value::Vector(ref vec_rc) => {
                        vec_rc.borrow_mut().push(push_value);
                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "vector push".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::VecGet => {
                // R[A] = R[B][R[C]]
                let dst = a;
                let vec_reg = b;
                let idx_reg = c;

                let vec_value = self.get_register(vec_reg)?.clone();
                let idx_value = self.get_register(idx_reg)?.clone();

                match (&vec_value, &idx_value) {
                    (Value::Vector(vec_rc), Value::Number(idx)) => {
                        let vec_borrowed = vec_rc.borrow();
                        let index = *idx as isize;

                        // Handle negative indices (Python-style)
                        let actual_idx = if index < 0 {
                            (vec_borrowed.len() as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= vec_borrowed.len() {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index,
                                vec_borrowed.len()
                            )));
                        }

                        let value = vec_borrowed[actual_idx].clone();
                        drop(vec_borrowed); // Explicitly drop the borrow
                        self.set_register(dst, value)?;
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Vector(_), _) => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Number".to_string(),
                        got: format!("{:?}", idx_value),
                    }),
                    _ => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::VecSet => {
                // R[A][R[B]] = R[C]
                let vec_reg = a;
                let idx_reg = b;
                let val_reg = c;

                let vec_value = self.get_register(vec_reg)?.clone();
                let idx_value = self.get_register(idx_reg)?.clone();
                let new_value = self.get_register(val_reg)?.clone();

                match (&vec_value, &idx_value) {
                    (Value::Vector(vec_rc), Value::Number(idx)) => {
                        let mut vec_borrowed = vec_rc.borrow_mut();
                        let index = *idx as isize;

                        // Handle negative indices (Python-style)
                        let actual_idx = if index < 0 {
                            (vec_borrowed.len() as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= vec_borrowed.len() {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index,
                                vec_borrowed.len()
                            )));
                        }

                        vec_borrowed[actual_idx] = new_value;
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Vector(_), _) => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Number".to_string(),
                        got: format!("{:?}", idx_value),
                    }),
                    _ => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::VecSlice => {
                // R[A] = R[B][R[C]..end]
                // Creates a new vector with elements from index R[C] to the end
                let dst = a;
                let vec_reg = b;
                let start_reg = c;

                let vec_value = self.get_register(vec_reg)?.clone();
                let start_value = self.get_register(start_reg)?.clone();

                match (&vec_value, &start_value) {
                    (Value::Vector(vec_rc), Value::Number(start_idx)) => {
                        let vec_borrowed = vec_rc.borrow();
                        let start = *start_idx as usize;

                        // Check bounds
                        if start > vec_borrowed.len() {
                            return Err(VmError::Runtime(format!(
                                "Slice start index out of bounds: {} (length: {})",
                                start,
                                vec_borrowed.len()
                            )));
                        }

                        // Create slice from start to end
                        let slice: Vec<Value> = vec_borrowed[start..].to_vec();
                        let slice_vec =
                            Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(slice)));

                        drop(vec_borrowed);
                        self.set_register(dst, slice_vec)?;
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Vector(_), _) => Err(VmError::TypeError {
                        operation: "vector slicing".to_string(),
                        expected: "Number".to_string(),
                        got: format!("{:?}", start_value),
                    }),
                    _ => Err(VmError::TypeError {
                        operation: "vector slicing".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            _ => unreachable!("Non-vector opcode in vector handler"),
        }
    }
}
