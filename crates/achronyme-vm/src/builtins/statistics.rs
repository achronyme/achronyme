//! Statistical functions
//!
//! This module provides statistical operations for the VM:
//! - sum: Sum of all elements
//! - mean: Average of elements
//! - std: Standard deviation

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Sum all elements in a vector or tensor
pub fn vm_sum(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "sum() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            if vec.is_empty() {
                return Ok(Value::Number(0.0));
            }

            let mut sum = 0.0;
            for val in vec.iter() {
                match val {
                    Value::Number(n) => sum += n,
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "sum".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Number(sum))
        }
        _ => Err(VmError::TypeError {
            operation: "sum".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate mean (average) of elements
pub fn vm_mean(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "mean() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            if vec.is_empty() {
                return Err(VmError::Runtime(
                    "mean() requires a non-empty vector".to_string(),
                ));
            }
            let count = vec.len() as f64;
            drop(vec);

            let sum_result = vm_sum(_vm, args)?;
            if let Value::Number(sum) = sum_result {
                Ok(Value::Number(sum / count))
            } else {
                Err(VmError::Runtime("sum() returned non-numeric value".to_string()))
            }
        }
        _ => Err(VmError::TypeError {
            operation: "mean".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate standard deviation
pub fn vm_std(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "std() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            if vec.len() < 2 {
                return Err(VmError::Runtime(
                    "std() requires a vector with at least 2 elements".to_string(),
                ));
            }

            // Calculate mean
            drop(vec);
            let mean_result = vm_mean(_vm, args)?;
            let mean = match mean_result {
                Value::Number(n) => n,
                _ => return Err(VmError::Runtime("mean() returned non-numeric value".to_string())),
            };

            // Calculate variance
            let vec = rc.borrow();
            let mut variance_sum = 0.0;
            for val in vec.iter() {
                match val {
                    Value::Number(n) => {
                        let diff = n - mean;
                        variance_sum += diff * diff;
                    }
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "std".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }

            let count = vec.len();
            let variance = variance_sum / (count - 1) as f64;
            Ok(Value::Number(variance.sqrt()))
        }
        _ => Err(VmError::TypeError {
            operation: "std".to_string(),
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
    fn test_sum_basic() {
        let mut vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_sum(&mut vm, &[Value::Vector(vec)]).unwrap();
        assert_eq!(result, Value::Number(15.0));
    }

    #[test]
    fn test_sum_empty() {
        let mut vm = setup_vm();
        let vec: Vec<Value> = vec![];
        let result = vm_sum(&mut vm, &[Value::Vector(vec)]).unwrap();
        assert_eq!(result, Value::Number(0.0));
    }

    #[test]
    fn test_mean_basic() {
        let mut vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_mean(&mut vm, &[Value::Vector(vec)]).unwrap();
        assert_eq!(result, Value::Number(3.0));
    }

    #[test]
    fn test_std_basic() {
        let mut vm = setup_vm();
        let vec = vec![Value::Number(2.0), Value::Number(4.0), Value::Number(4.0), Value::Number(4.0), Value::Number(5.0), Value::Number(5.0), Value::Number(7.0), Value::Number(9.0)];
        let result = vm_std(&mut vm, &[Value::Vector(vec)]).unwrap();
        // Expected std dev ≈ 2.138
        if let Value::Number(n) = result {
            assert!((n - 2.138).abs() < 0.01);
        } else {
            panic!("Expected Number");
        }
    }
}
