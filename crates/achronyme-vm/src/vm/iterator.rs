//! Iterator and Builder infrastructure for Higher-Order Functions
//!
//! This module provides the foundation for HOF operations by offering:
//! - VmIterator: Safe, uniform iteration over all collection types
//! - VmBuilder: Efficient construction of result collections with type preservation

use crate::error::VmError;
use crate::value::Value;
use std::cell::RefCell;
use std::rc::Rc;

/// VM-level iterator abstraction for safe traversal of collections
///
/// Provides a uniform interface for iterating over different collection types
/// while maintaining safety and proper UTF-8 handling for strings.
#[derive(Clone, Debug)]
pub enum VmIterator {
    /// Vector iterator: Direct access (fast)
    Vector {
        data: Rc<RefCell<Vec<Value>>>,
        len: usize,
        index: usize,
    },

    /// String iterator: Safe UTF-8 iteration
    String {
        chars: Vec<char>, // Pre-collected for safe indexing
        index: usize,
    },

    /// Tensor iterator: Linear iteration over contiguous buffer
    Tensor {
        data: Vec<f64>, // Cloned for safety
        index: usize,
    },

    /// Range iterator: Numeric ranges
    Range { current: f64, end: f64, step: f64 },
}

impl VmIterator {
    /// Create iterator from a Value
    ///
    /// # Arguments
    /// * `value` - The collection value to iterate over
    ///
    /// # Returns
    /// * `Ok(VmIterator)` - Successfully created iterator
    /// * `Err(VmError)` - Value is not iterable
    pub fn from_value(value: &Value) -> Result<Self, VmError> {
        match value {
            Value::Vector(rc) => {
                let len = rc.borrow().len();
                Ok(VmIterator::Vector {
                    data: rc.clone(),
                    len,
                    index: 0,
                })
            }

            Value::String(s) => {
                let chars: Vec<char> = s.chars().collect();
                Ok(VmIterator::String { chars, index: 0 })
            }

            Value::Tensor(tensor) => Ok(VmIterator::Tensor {
                data: tensor.data().to_vec(),
                index: 0,
            }),

            _ => Err(VmError::TypeError {
                operation: "iterator creation".to_string(),
                expected: "Vector, String, or Tensor".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }

    /// Get next value, returns None when exhausted
    ///
    /// # Returns
    /// * `Some(Value)` - Next value in the iteration
    /// * `None` - Iterator is exhausted
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Value> {
        match self {
            VmIterator::Vector { data, len, index } => {
                if *index >= *len {
                    return None;
                }
                let val = data.borrow()[*index].clone();
                *index += 1;
                Some(val)
            }

            VmIterator::String { chars, index } => {
                if *index >= chars.len() {
                    return None;
                }
                let ch = chars[*index];
                *index += 1;
                Some(Value::String(ch.to_string()))
            }

            VmIterator::Tensor { data, index } => {
                if *index >= data.len() {
                    return None;
                }
                let val = data[*index];
                *index += 1;
                Some(Value::Number(val))
            }

            VmIterator::Range { current, end, step } => {
                if (*step > 0.0 && *current >= *end) || (*step < 0.0 && *current <= *end) {
                    return None;
                }
                let val = *current;
                *current += *step;
                Some(Value::Number(val))
            }
        }
    }

    /// Check if iterator is exhausted
    ///
    /// # Returns
    /// * `true` - Iterator has no more elements
    /// * `false` - Iterator has more elements
    pub fn is_done(&self) -> bool {
        match self {
            VmIterator::Vector { index, len, .. } => index >= len,
            VmIterator::String { chars, index } => *index >= chars.len(),
            VmIterator::Tensor { data, index } => *index >= data.len(),
            VmIterator::Range { current, end, step } => {
                (*step > 0.0 && *current >= *end) || (*step < 0.0 && *current <= *end)
            }
        }
    }

    /// Reset iterator to beginning
    pub fn reset(&mut self) {
        match self {
            VmIterator::Vector { index, .. } => *index = 0,
            VmIterator::String { index, .. } => *index = 0,
            VmIterator::Tensor { index, .. } => *index = 0,
            VmIterator::Range { .. } => {
                // Cannot reset range iterator (would need original start)
            }
        }
    }
}

/// Builder for constructing collections during HOF operations
///
/// Provides efficient collection building with automatic type preservation
/// when possible. If incompatible types are mixed, gracefully decays to
/// a generic Vector.
#[derive(Debug, Clone)]
pub enum VmBuilder {
    /// Vector builder (default, always safe)
    Vector(Vec<Value>),

    /// Tensor builder (tries to maintain tensor type, decays to Vector if needed)
    Tensor {
        data: Vec<f64>,
        shape: Vec<usize>,
        can_stay_tensor: bool, // False if non-numeric value encountered
    },

    /// String builder (for string transformations)
    String(String),
}

impl VmBuilder {
    /// Create builder from hint value (tries to preserve type)
    ///
    /// # Arguments
    /// * `hint` - A value indicating the desired output type
    ///
    /// # Returns
    /// Builder configured to match the hint type when possible
    pub fn from_hint(hint: &Value) -> Self {
        match hint {
            Value::Tensor(_) => VmBuilder::Tensor {
                data: Vec::new(),
                shape: vec![0], // Will be updated
                can_stay_tensor: true,
            },
            Value::String(_) => VmBuilder::String(String::new()),
            _ => VmBuilder::Vector(Vec::new()),
        }
    }

    /// Create a generic vector builder
    pub fn new_vector() -> Self {
        VmBuilder::Vector(Vec::new())
    }

    /// Create a tensor builder
    pub fn new_tensor() -> Self {
        VmBuilder::Tensor {
            data: Vec::new(),
            shape: vec![0],
            can_stay_tensor: true,
        }
    }

    /// Create a string builder
    pub fn new_string() -> Self {
        VmBuilder::String(String::new())
    }

    /// Push a value into the builder
    ///
    /// # Arguments
    /// * `value` - Value to add to the collection
    ///
    /// # Returns
    /// * `Ok(())` - Value successfully added
    /// * `Err(VmError)` - Type mismatch or other error
    pub fn push(&mut self, value: Value) -> Result<(), VmError> {
        match self {
            VmBuilder::Vector(vec) => {
                vec.push(value);
                Ok(())
            }

            VmBuilder::Tensor {
                data,
                can_stay_tensor,
                ..
            } => {
                // Try to extract number
                match value {
                    Value::Number(n) => {
                        if *can_stay_tensor {
                            data.push(n);
                            Ok(())
                        } else {
                            // Already decayed, this shouldn't happen
                            Err(VmError::Runtime("Tensor builder already decayed".into()))
                        }
                    }
                    _ => {
                        // Decay to vector
                        *can_stay_tensor = false;
                        // Convert existing data to Vector
                        let mut vec: Vec<Value> = data.iter().map(|&n| Value::Number(n)).collect();
                        vec.push(value);
                        *self = VmBuilder::Vector(vec);
                        Ok(())
                    }
                }
            }

            VmBuilder::String(s) => match value {
                Value::String(str_val) => {
                    s.push_str(&str_val);
                    Ok(())
                }
                _ => Err(VmError::TypeError {
                    operation: "string builder".to_string(),
                    expected: "String".to_string(),
                    got: format!("{:?}", value),
                }),
            },
        }
    }

    /// Finalize and convert to Value
    ///
    /// Consumes the builder and produces the final collection value.
    ///
    /// # Returns
    /// * `Ok(Value)` - The constructed collection
    /// * `Err(VmError)` - Failed to construct (e.g., invalid tensor dimensions)
    pub fn finalize(self) -> Result<Value, VmError> {
        match self {
            VmBuilder::Vector(vec) => Ok(Value::Vector(Rc::new(RefCell::new(vec)))),

            VmBuilder::Tensor {
                data,
                can_stay_tensor,
                ..
            } => {
                if can_stay_tensor {
                    use achronyme_types::tensor::RealTensor;
                    let shape = vec![data.len()];
                    match RealTensor::new(data, shape) {
                        Ok(tensor) => Ok(Value::Tensor(tensor)),
                        Err(e) => Err(VmError::Runtime(format!(
                            "Failed to create tensor: {:?}",
                            e
                        ))),
                    }
                } else {
                    // Shouldn't reach here due to decay logic
                    Err(VmError::Runtime("Tensor builder in invalid state".into()))
                }
            }

            VmBuilder::String(s) => Ok(Value::String(s)),
        }
    }

    /// Get the current size of the builder
    pub fn len(&self) -> usize {
        match self {
            VmBuilder::Vector(vec) => vec.len(),
            VmBuilder::Tensor { data, .. } => data.len(),
            VmBuilder::String(s) => s.len(),
        }
    }

    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_iterator() {
        let vec = Rc::new(RefCell::new(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
        ]));

        let mut iter = VmIterator::from_value(&Value::Vector(vec)).unwrap();

        assert!(!iter.is_done());
        assert_eq!(iter.next(), Some(Value::Number(1.0)));
        assert_eq!(iter.next(), Some(Value::Number(2.0)));
        assert_eq!(iter.next(), Some(Value::Number(3.0)));
        assert_eq!(iter.next(), None);
        assert!(iter.is_done());
    }

    #[test]
    fn test_string_iterator() {
        let mut iter = VmIterator::from_value(&Value::String("abc".to_string())).unwrap();

        assert_eq!(iter.next(), Some(Value::String("a".to_string())));
        assert_eq!(iter.next(), Some(Value::String("b".to_string())));
        assert_eq!(iter.next(), Some(Value::String("c".to_string())));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_string_iterator_unicode() {
        let mut iter = VmIterator::from_value(&Value::String("😀🎉".to_string())).unwrap();

        assert_eq!(iter.next(), Some(Value::String("😀".to_string())));
        assert_eq!(iter.next(), Some(Value::String("🎉".to_string())));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_tensor_iterator() {
        use achronyme_types::tensor::RealTensor;
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0], vec![3]).unwrap();
        let mut iter = VmIterator::from_value(&Value::Tensor(tensor)).unwrap();

        assert_eq!(iter.next(), Some(Value::Number(1.0)));
        assert_eq!(iter.next(), Some(Value::Number(2.0)));
        assert_eq!(iter.next(), Some(Value::Number(3.0)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_range_iterator() {
        let mut iter = VmIterator::Range {
            current: 0.0,
            end: 3.0,
            step: 1.0,
        };

        assert_eq!(iter.next(), Some(Value::Number(0.0)));
        assert_eq!(iter.next(), Some(Value::Number(1.0)));
        assert_eq!(iter.next(), Some(Value::Number(2.0)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_vector_builder() {
        let mut builder = VmBuilder::new_vector();

        builder.push(Value::Number(1.0)).unwrap();
        builder.push(Value::Number(2.0)).unwrap();
        builder.push(Value::String("test".to_string())).unwrap();

        let result = builder.finalize().unwrap();
        match result {
            Value::Vector(vec) => {
                let v = vec.borrow();
                assert_eq!(v.len(), 3);
                assert_eq!(v[0], Value::Number(1.0));
                assert_eq!(v[2], Value::String("test".to_string()));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_tensor_builder_pure_numeric() {
        let mut builder = VmBuilder::new_tensor();

        builder.push(Value::Number(1.0)).unwrap();
        builder.push(Value::Number(2.0)).unwrap();
        builder.push(Value::Number(3.0)).unwrap();

        let result = builder.finalize().unwrap();
        match result {
            Value::Tensor(tensor) => {
                assert_eq!(tensor.data(), &vec![1.0, 2.0, 3.0]);
            }
            _ => panic!("Expected Tensor"),
        }
    }

    #[test]
    fn test_tensor_builder_decay() {
        let mut builder = VmBuilder::new_tensor();

        builder.push(Value::Number(1.0)).unwrap();
        builder.push(Value::String("oops".to_string())).unwrap();
        builder.push(Value::Number(3.0)).unwrap();

        let result = builder.finalize().unwrap();
        match result {
            Value::Vector(vec) => {
                let v = vec.borrow();
                assert_eq!(v.len(), 3);
                assert_eq!(v[0], Value::Number(1.0));
                assert_eq!(v[1], Value::String("oops".to_string()));
            }
            _ => panic!("Expected Vector after decay"),
        }
    }

    #[test]
    fn test_string_builder() {
        let mut builder = VmBuilder::new_string();

        builder.push(Value::String("Hello".to_string())).unwrap();
        builder.push(Value::String(" ".to_string())).unwrap();
        builder.push(Value::String("World".to_string())).unwrap();

        let result = builder.finalize().unwrap();
        match result {
            Value::String(s) => {
                assert_eq!(s, "Hello World");
            }
            _ => panic!("Expected String"),
        }
    }

    #[test]
    fn test_builder_from_hint() {
        use achronyme_types::tensor::RealTensor;
        // Test Vector hint
        let vec_hint = Value::Vector(Rc::new(RefCell::new(vec![])));
        let builder = VmBuilder::from_hint(&vec_hint);
        assert!(matches!(builder, VmBuilder::Vector(_)));

        // Test Tensor hint
        let tensor_hint = Value::Tensor(RealTensor::new(vec![1.0], vec![1]).unwrap());
        let builder = VmBuilder::from_hint(&tensor_hint);
        assert!(matches!(builder, VmBuilder::Tensor { .. }));

        // Test String hint
        let string_hint = Value::String("test".to_string());
        let builder = VmBuilder::from_hint(&string_hint);
        assert!(matches!(builder, VmBuilder::String(_)));
    }
}
