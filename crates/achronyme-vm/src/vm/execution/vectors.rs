//! Vector and Tensor instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use achronyme_types::tensor::{ComplexTensor, RealTensor, Tensor};

impl VM {
    /// Execute vector and tensor instructions
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

            OpCode::VecSpread => {
                // R[A].spread(R[B])
                let vec_reg = a;
                let spread_reg = b;

                let vec_value = self.get_register(vec_reg)?.clone();
                let spread_value = self.get_register(spread_reg)?.clone();

                match vec_value {
                    Value::Vector(ref vec_rc) => {
                        let mut target_vec = vec_rc.borrow_mut();

                        // Check what we are spreading
                        match spread_value {
                            Value::Vector(src_vec_rc) => {
                                let src_vec = src_vec_rc.borrow();
                                target_vec.extend(src_vec.iter().cloned());
                            }
                            Value::Tensor(t) => {
                                // Spread tensor elements (flattened)
                                for val in t.data() {
                                    target_vec.push(Value::Number(*val));
                                }
                            }
                            Value::ComplexTensor(t) => {
                                for val in t.data() {
                                    target_vec.push(Value::Complex(*val));
                                }
                            }
                            Value::String(s) => {
                                // Spread string as characters
                                for c in s.chars() {
                                    target_vec.push(Value::String(c.to_string()));
                                }
                            }
                            // Could also support Generator/Iterator spreading if needed
                            // But that requires more complex handling (consuming the iterator)
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "spread".to_string(),
                                    expected: "Vector, Tensor, or String".to_string(),
                                    got: format!("{:?}", spread_value),
                                });
                            }
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "vector spread".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::VecGet => {
                // R[A] = R[B][R[C]] (supports Vector and Tensor 1D indexing)
                let dst = a;
                let vec_reg = b;
                let idx_reg = c;

                let vec_value = self.get_register(vec_reg)?.clone();
                let idx_value = self.get_register(idx_reg)?.clone();

                match (&vec_value, &idx_value) {
                    (Value::Vector(vec_rc), Value::Number(idx)) => {
                        let vec_borrowed = vec_rc.borrow();
                        let len = vec_borrowed.len();
                        let index = *idx as isize;
                        let actual_idx = if index < 0 {
                            (len as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= len {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index, len
                            )));
                        }

                        let value = vec_borrowed[actual_idx].clone();
                        drop(vec_borrowed);
                        self.set_register(dst, value)?;
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Tensor(t), Value::Number(idx)) => {
                        if t.rank() == 0 {
                            return Err(VmError::Runtime("Cannot index scalar tensor".to_string()));
                        }
                        let len = t.shape()[0];
                        let index = *idx as isize;
                        let actual_idx = if index < 0 {
                            (len as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= len {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index, len
                            )));
                        }

                        if t.rank() == 1 {
                            // Return scalar
                            let val = t.data[actual_idx]; // Stride is 1
                            self.set_register(dst, Value::Number(val))?;
                        } else {
                            // Return sub-tensor
                            let stride = t.strides()[0];
                            let start = actual_idx * stride;
                            let end = start + stride;
                            let new_data = t.data[start..end].to_vec();
                            let new_shape = t.shape()[1..].to_vec();
                            let new_t = RealTensor::new(new_data, new_shape)
                                .map_err(|e| VmError::Runtime(e.to_string()))?;
                            self.set_register(dst, Value::Tensor(new_t))?;
                        }
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::ComplexTensor(t), Value::Number(idx)) => {
                        if t.rank() == 0 {
                            return Err(VmError::Runtime("Cannot index scalar tensor".to_string()));
                        }
                        let len = t.shape()[0];
                        let index = *idx as isize;
                        let actual_idx = if index < 0 {
                            (len as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= len {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index, len
                            )));
                        }

                        if t.rank() == 1 {
                            // Return scalar
                            let val = t.data[actual_idx]; // Stride is 1
                            self.set_register(dst, Value::Complex(val))?;
                        } else {
                            // Return sub-tensor
                            let stride = t.strides()[0];
                            let start = actual_idx * stride;
                            let end = start + stride;
                            let new_data = t.data[start..end].to_vec();
                            let new_shape = t.shape()[1..].to_vec();
                            let new_t = ComplexTensor::new(new_data, new_shape)
                                .map_err(|e| VmError::Runtime(e.to_string()))?;
                            self.set_register(dst, Value::ComplexTensor(new_t))?;
                        }
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::String(s), Value::Number(idx)) => {
                        let char_count = s.chars().count();
                        let index = *idx as isize;
                        let actual_idx = if index < 0 {
                            (char_count as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= char_count {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index, char_count
                            )));
                        }

                        if let Some(c) = s.chars().nth(actual_idx) {
                            self.set_register(dst, Value::String(c.to_string()))?;
                        }
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Vector(_), _) => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Number".to_string(),
                        got: format!("{:?}", idx_value),
                    }),
                    _ => Err(VmError::TypeError {
                        operation: "indexing".to_string(),
                        expected: "Vector or Tensor".to_string(),
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
                        let len = vec_borrowed.len();
                        let actual_idx = if index < 0 {
                            (len as isize + index) as usize
                        } else {
                            index as usize
                        };

                        if actual_idx >= len {
                            return Err(VmError::Runtime(format!(
                                "Index out of bounds: {} (length: {})",
                                index, len
                            )));
                        }

                        vec_borrowed[actual_idx] = new_value;
                        Ok(ExecutionResult::Continue)
                    }
                    (Value::Tensor(_), _) | (Value::ComplexTensor(_), _) => Err(VmError::Runtime(
                        "Cannot mutate immutable Tensor in-place. Use 'set' function or recreate."
                            .to_string(),
                    )),
                    _ => Err(VmError::TypeError {
                        operation: "vector indexing".to_string(),
                        expected: "Vector".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::VecSlice => {
                // R[A] = R[B][R[C]..R[C+1]]
                let dst = a;
                let vec_reg = b;
                let start_reg = c;
                let end_reg = c.wrapping_add(1);

                let vec_value = self.get_register(vec_reg)?.clone();
                let start_val = self.get_register(start_reg)?;
                let end_val = self.get_register(end_reg)?;

                match vec_value {
                    Value::Vector(vec_rc) => {
                        let vec = vec_rc.borrow();
                        let len = vec.len();

                        let start = match start_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => 0,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice start".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", start_val),
                                })
                            }
                        };

                        let end = match end_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => len,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice end".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", end_val),
                                })
                            }
                        };

                        let end = end.max(start);
                        let slice: Vec<Value> = vec[start..end].to_vec();
                        let slice_vec =
                            Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(slice)));

                        self.set_register(dst, slice_vec)?;
                        Ok(ExecutionResult::Continue)
                    }
                    Value::Tensor(t) => {
                        // Slice dim 0
                        if t.rank() == 0 {
                            return Err(VmError::Runtime("Cannot slice scalar tensor".to_string()));
                        }
                        let len = t.shape()[0];

                        let start = match start_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => 0,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice start".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", start_val),
                                })
                            }
                        };

                        let end = match end_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => len,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice end".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", end_val),
                                })
                            }
                        };

                        let end = end.max(start);
                        let new_len = end - start;

                        let stride = t.strides()[0];
                        let start_offset = start * stride;
                        let end_offset = end * stride;

                        let slice_data = t.data[start_offset..end_offset].to_vec();
                        let mut new_shape = t.shape().to_vec();
                        new_shape[0] = new_len;

                        let new_t = RealTensor::new(slice_data, new_shape)
                            .map_err(|e| VmError::Runtime(e.to_string()))?;
                        self.set_register(dst, Value::Tensor(new_t))?;
                        Ok(ExecutionResult::Continue)
                    }
                    Value::ComplexTensor(t) => {
                        // Same logic for complex
                        if t.rank() == 0 {
                            return Err(VmError::Runtime("Cannot slice scalar tensor".to_string()));
                        }
                        let len = t.shape()[0];

                        let start = match start_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => 0,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice start".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", start_val),
                                })
                            }
                        };

                        let end = match end_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (len as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(len)
                                }
                            }
                            Value::Null => len,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice end".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", end_val),
                                })
                            }
                        };

                        let end = end.max(start);
                        let new_len = end - start;

                        let stride = t.strides()[0];
                        let start_offset = start * stride;
                        let end_offset = end * stride;

                        let slice_data = t.data[start_offset..end_offset].to_vec();
                        let mut new_shape = t.shape().to_vec();
                        new_shape[0] = new_len;

                        let new_t = ComplexTensor::new(slice_data, new_shape)
                            .map_err(|e| VmError::Runtime(e.to_string()))?;
                        self.set_register(dst, Value::ComplexTensor(new_t))?;
                        Ok(ExecutionResult::Continue)
                    }
                    Value::String(s) => {
                        let char_count = s.chars().count();

                        let start = match start_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (char_count as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(char_count)
                                }
                            }
                            Value::Null => 0,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice start".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", start_val),
                                })
                            }
                        };

                        let end = match end_val {
                            Value::Number(n) => {
                                let idx = *n as isize;
                                if idx < 0 {
                                    (char_count as isize + idx).max(0) as usize
                                } else {
                                    (idx as usize).min(char_count)
                                }
                            }
                            Value::Null => char_count,
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: "slice end".to_string(),
                                    expected: "Number or Null".to_string(),
                                    got: format!("{:?}", end_val),
                                })
                            }
                        };

                        let end = end.max(start);
                        let slice: String = s.chars().skip(start).take(end - start).collect();
                        self.set_register(dst, Value::String(slice))?;
                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "slicing".to_string(),
                        expected: "Vector or Tensor".to_string(),
                        got: format!("{:?}", vec_value),
                    }),
                }
            }

            OpCode::RangeEx => {
                // R[A] = R[B]..R[C] (Create Range value)
                let dst = a;
                let start_reg = b;
                let end_reg = c;

                let start = self.get_register(start_reg)?.clone();
                let end = self.get_register(end_reg)?.clone();

                let range = Value::Range {
                    start: Box::new(start),
                    end: Box::new(end),
                    inclusive: false,
                };
                self.set_register(dst, range)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::TensorGet => {
                // R[A] = R[B][indices...]
                // A = dest, B = tensor, C = indices_start_reg.
                // Indices count is NOT passed directly?
                // We assume consecutive registers from C.
                // How many? We must check rank of tensor.
                // IF we support partial indexing, we need to know count.
                // Let's assume standard ABI: TensorGet takes count in C? No, C is start reg.
                // Wait, we redefined ABI in Plan:
                // `TensorGet` A=dest, B=base_reg, C=count.
                // R[B] = tensor. R[B+1]... = indices.
                // This is consistent with Call.

                let dst = a;
                let base = b;
                let count = c as usize;

                let tensor_val = self.get_register(base)?.clone();
                let mut indices = Vec::with_capacity(count);
                for i in 0..count {
                    let idx_reg = base.wrapping_add(1).wrapping_add(i as u8);
                    indices.push(self.get_register(idx_reg)?.clone());
                }

                // Automatic Type Promotion: Check if we have a nested Vector that should be a Tensor
                // This allows matrix[i, j] where matrix is defined as [[1,2], [3,4]]
                let promoted_tensor = if let Value::Vector(_) = tensor_val {
                    tensor_val.try_to_tensor()
                } else {
                    None
                };

                let target_val = promoted_tensor.as_ref().unwrap_or(&tensor_val);

                match target_val {
                    Value::Tensor(t) => self.slice_tensor_generic(dst, t, &indices),
                    Value::ComplexTensor(t) => self.slice_complex_tensor_generic(dst, t, &indices),
                    // Fallback to chained indexing for Vectors if applicable?
                    Value::Vector(_) | Value::String(_) => {
                        // ... existing fallback ...
                        if count == 1 {
                            let idx = &indices[0];
                            match idx {
                                Value::Range {
                                    start: _,
                                    end: _,
                                    inclusive: _,
                                } => Err(VmError::Runtime(
                                    "Range slicing on Vector via TensorGet not yet specialized"
                                        .to_string(),
                                )),
                                _ => Err(VmError::TypeError {
                                    operation: "multidim indexing".to_string(),
                                    expected: "Tensor".to_string(),
                                    got: "Vector".to_string(),
                                }),
                            }
                        } else {
                            Err(VmError::TypeError {
                                operation: "multidim indexing".to_string(),
                                expected: "Tensor".to_string(),
                                got: "Vector (nested vectors not supported in TensorGet - failed to promote)".to_string(),
                            })
                        }
                    }
                    _ => Err(VmError::TypeError {
                        operation: "tensor indexing".to_string(),
                        expected: "Tensor".to_string(),
                        got: format!("{:?}", target_val),
                    }),
                }
            }

            _ => unreachable!("Non-vector opcode in vector handler"),
        }
    }

    // Helper for generic tensor slicing
    fn slice_tensor_generic(
        &mut self,
        dst: u8,
        t: &RealTensor,
        indices: &[Value],
    ) -> Result<ExecutionResult, VmError> {
        let new_tensor = self.perform_tensor_slicing(t, indices)?;
        self.set_register(dst, Value::Tensor(new_tensor))?;
        Ok(ExecutionResult::Continue)
    }

    fn slice_complex_tensor_generic(
        &mut self,
        dst: u8,
        t: &ComplexTensor,
        indices: &[Value],
    ) -> Result<ExecutionResult, VmError> {
        let new_tensor = self.perform_tensor_slicing(t, indices)?;
        self.set_register(dst, Value::ComplexTensor(new_tensor))?;
        Ok(ExecutionResult::Continue)
    }

    // Generic implementation that returns Tensor<T>
    fn perform_tensor_slicing<T: Clone>(
        &mut self,
        t: &Tensor<T>,
        indices: &[Value],
    ) -> Result<Tensor<T>, VmError> {
        let rank = t.rank();
        if indices.len() > rank {
            return Err(VmError::Runtime(format!(
                "Too many indices: {} for rank {}",
                indices.len(),
                rank
            )));
        }

        let mut ranges = Vec::new();
        let mut squeeze_dims = Vec::new();

        for (i, idx_val) in indices.iter().enumerate() {
            let dim_len = t.shape()[i];
            match idx_val {
                Value::Number(n) => {
                    let idx = *n as isize;
                    let actual = if idx < 0 {
                        (dim_len as isize + idx) as usize
                    } else {
                        idx as usize
                    };
                    if actual >= dim_len {
                        return Err(VmError::Runtime(format!(
                            "Index {} out of bounds for dim {} (len {})",
                            idx, i, dim_len
                        )));
                    }
                    ranges.push((actual, actual + 1));
                    squeeze_dims.push(true);
                }
                Value::Range {
                    start,
                    end,
                    inclusive,
                } => {
                    let s = match &**start {
                        Value::Number(n) => {
                            let idx = *n as isize;
                            if idx < 0 {
                                (dim_len as isize + idx).max(0) as usize
                            } else {
                                (idx as usize).min(dim_len)
                            }
                        }
                        Value::Null => 0,
                        _ => return Err(VmError::Runtime("Invalid start index".to_string())),
                    };
                    let mut e = match &**end {
                        Value::Number(n) => {
                            let idx = *n as isize;
                            if idx < 0 {
                                (dim_len as isize + idx).max(0) as usize
                            } else {
                                (idx as usize).min(dim_len)
                            }
                        }
                        Value::Null => dim_len,
                        _ => return Err(VmError::Runtime("Invalid end index".to_string())),
                    };
                    if *inclusive {
                        e = (e + 1).min(dim_len);
                    }
                    e = e.max(s);
                    ranges.push((s, e));
                    squeeze_dims.push(false);
                }
                Value::Null => {
                    ranges.push((0, dim_len));
                    squeeze_dims.push(false);
                }
                _ => {
                    return Err(VmError::Runtime(format!(
                        "Invalid index type: {:?}",
                        idx_val
                    )))
                }
            }
        }

        for i in indices.len()..rank {
            let dim_len = t.shape()[i];
            ranges.push((0, dim_len));
            squeeze_dims.push(false);
        }

        let mut new_shape = Vec::new();
        for (i, &(start, end)) in ranges.iter().enumerate() {
            if !squeeze_dims[i] {
                new_shape.push(end - start);
            }
        }

        if new_shape.is_empty() {
            // Scalar result - create rank-0 tensor?
            // Or should we return Value::Number?
            // TensorGet usually returns Value.
            // But this function returns Tensor<T>.
            // If shape is empty, it is a rank-0 tensor (scalar).
            // We must return Tensor<T> with empty shape and 1 element.
            let mut offset = 0;
            for (i, &(start, _)) in ranges.iter().enumerate() {
                offset += start * t.strides()[i];
            }
            let val = t.data()[offset].clone();
            return Tensor::new(vec![val], vec![]).map_err(|e| VmError::Runtime(e.to_string()));
        }

        let total_elements: usize = new_shape.iter().product();
        let mut new_data = Vec::with_capacity(total_elements);

        let mut counters = vec![0; rank];
        for i in 0..rank {
            counters[i] = ranges[i].0;
        }

        loop {
            let mut offset = 0;
            for i in 0..rank {
                offset += counters[i] * t.strides()[i];
            }
            new_data.push(t.data()[offset].clone());

            let mut i = rank - 1;
            loop {
                counters[i] += 1;
                if counters[i] < ranges[i].1 {
                    break;
                } else {
                    counters[i] = ranges[i].0;
                    if i == 0 {
                        return Tensor::new(new_data, new_shape)
                            .map_err(|e| VmError::Runtime(e.to_string()));
                    }
                    i -= 1;
                }
            }
        }
    }
}
