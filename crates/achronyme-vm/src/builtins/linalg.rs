//! Linear algebra functions
//!
//! This module provides linear algebra operations for the VM:
//! - dot: Dot product of two vectors
//! - cross: Cross product of two 3D vectors
//! - norm: Euclidean norm (magnitude) of a vector
//! - normalize: Normalize a vector to unit length

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Calculate dot product of two vectors
pub fn vm_dot(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }

    match (&args[0], &args[1]) {
        (Value::Vector(v1), Value::Vector(v2)) => {
            if v1.len() != v2.len() {
                return Err(VmError::RuntimeError(format!(
                    "dot() requires vectors of same length, got {} and {}",
                    v1.len(),
                    v2.len()
                )));
            }

            let mut sum = 0.0;
            for (val1, val2) in v1.iter().zip(v2.iter()) {
                match (val1, val2) {
                    (Value::Number(n1), Value::Number(n2)) => sum += n1 * n2,
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "dot".to_string(),
                            expected: "numeric vectors".to_string(),
                            got: format!("{:?}, {:?}", val1, val2),
                        })
                    }
                }
            }
            Ok(Value::Number(sum))
        }
        _ => Err(VmError::TypeError {
            operation: "dot".to_string(),
            expected: "two Vectors".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Calculate cross product of two 3D vectors
pub fn vm_cross(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }

    match (&args[0], &args[1]) {
        (Value::Vector(v1), Value::Vector(v2)) => {
            if v1.len() != 3 || v2.len() != 3 {
                return Err(VmError::RuntimeError(
                    "cross() requires 3D vectors".to_string(),
                ));
            }

            let (x1, y1, z1) = match (&v1[0], &v1[1], &v1[2]) {
                (Value::Number(x), Value::Number(y), Value::Number(z)) => (*x, *y, *z),
                _ => {
                    return Err(VmError::TypeError {
                        operation: "cross".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?}", v1),
                    })
                }
            };

            let (x2, y2, z2) = match (&v2[0], &v2[1], &v2[2]) {
                (Value::Number(x), Value::Number(y), Value::Number(z)) => (*x, *y, *z),
                _ => {
                    return Err(VmError::TypeError {
                        operation: "cross".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?}", v2),
                    })
                }
            };

            let result = vec![
                Value::Number(y1 * z2 - z1 * y2),
                Value::Number(z1 * x2 - x1 * z2),
                Value::Number(x1 * y2 - y1 * x2),
            ];

            Ok(Value::Vector(result))
        }
        _ => Err(VmError::TypeError {
            operation: "cross".to_string(),
            expected: "two Vectors".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Calculate Euclidean norm (magnitude) of a vector
pub fn vm_norm(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Vector(vec) => {
            let mut sum_sq = 0.0;
            for val in vec.iter() {
                match val {
                    Value::Number(n) => sum_sq += n * n,
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "norm".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Number(sum_sq.sqrt()))
        }
        _ => Err(VmError::TypeError {
            operation: "norm".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Normalize a vector to unit length
pub fn vm_normalize(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Vector(vec) => {
            // Calculate norm
            let norm_result = vm_norm(_vm, args)?;
            let norm = match norm_result {
                Value::Number(n) => n,
                _ => return Err(VmError::RuntimeError("norm() returned non-numeric value".to_string())),
            };

            if norm == 0.0 {
                return Err(VmError::RuntimeError(
                    "Cannot normalize zero vector".to_string(),
                ));
            }

            // Divide each element by norm
            let mut normalized = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => normalized.push(Value::Number(n / norm)),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "normalize".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }

            Ok(Value::Vector(normalized))
        }
        _ => Err(VmError::TypeError {
            operation: "normalize".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_vm() -> VM {
        VM::new()
    }

    #[test]
    fn test_dot_basic() {
        let mut vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)];
        let v2 = vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)];
        let result = vm_dot(&mut vm, &[Value::Vector(v1), Value::Vector(v2)]).unwrap();
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Value::Number(32.0));
    }

    #[test]
    fn test_cross_basic() {
        let mut vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(0.0), Value::Number(0.0)];
        let v2 = vec![Value::Number(0.0), Value::Number(1.0), Value::Number(0.0)];
        let result = vm_cross(&mut vm, &[Value::Vector(v1), Value::Vector(v2)]).unwrap();
        // i × j = k = [0, 0, 1]
        match result {
            Value::Vector(v) => {
                assert_eq!(v.len(), 3);
                assert_eq!(v[0], Value::Number(0.0));
                assert_eq!(v[1], Value::Number(0.0));
                assert_eq!(v[2], Value::Number(1.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_norm_basic() {
        let mut vm = setup_vm();
        let v = vec![Value::Number(3.0), Value::Number(4.0)];
        let result = vm_norm(&mut vm, &[Value::Vector(v)]).unwrap();
        // sqrt(3^2 + 4^2) = sqrt(9 + 16) = sqrt(25) = 5
        assert_eq!(result, Value::Number(5.0));
    }

    #[test]
    fn test_normalize_basic() {
        let mut vm = setup_vm();
        let v = vec![Value::Number(3.0), Value::Number(4.0)];
        let result = vm_normalize(&mut vm, &[Value::Vector(v)]).unwrap();
        match result {
            Value::Vector(normalized) => {
                assert_eq!(normalized.len(), 2);
                // Should be [3/5, 4/5] = [0.6, 0.8]
                if let Value::Number(n) = normalized[0] {
                    assert!((n - 0.6).abs() < 0.001);
                }
                if let Value::Number(n) = normalized[1] {
                    assert!((n - 0.8).abs() < 0.001);
                }
            }
            _ => panic!("Expected Vector"),
        }
    }
}
