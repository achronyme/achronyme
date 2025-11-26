//! Statistical functions
//!
//! This module provides statistical operations for the VM:
//! - sum: Sum of all elements
//! - mean: Average of elements
//! - std: Standard deviation

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::complex::Complex;

/// Sum all elements in a vector or tensor
pub fn vm_sum(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "sum() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read();
            if vec.is_empty() {
                return Ok(Value::Number(0.0));
            }

            let mut sum_re = 0.0;
            let mut sum_im = 0.0;
            let mut is_complex = false;

            for val in vec.iter() {
                match val {
                    Value::Number(n) => sum_re += n,
                    Value::Complex(c) => {
                        sum_re += c.re;
                        sum_im += c.im;
                        is_complex = true;
                    }
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "sum".to_string(),
                            expected: "numeric or complex vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }

            if is_complex {
                Ok(Value::Complex(Complex::new(sum_re, sum_im)))
            } else {
                Ok(Value::Number(sum_re))
            }
        }
        Value::Tensor(t) => {
            let sum: f64 = t.data().iter().sum();
            Ok(Value::Number(sum))
        }
        Value::ComplexTensor(t) => {
            let mut sum = Complex::new(0.0, 0.0);
            for c in t.data() {
                sum = sum + *c;
            }
            Ok(Value::Complex(sum))
        }
        _ => Err(VmError::TypeError {
            operation: "sum".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate mean (average) of elements
pub fn vm_mean(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "mean() expects 1 argument, got {}",
            args.len()
        )));
    }

    let count = match &args[0] {
        Value::Vector(rc) => rc.read().len(),
        Value::Tensor(t) => t.size(),
        Value::ComplexTensor(t) => t.size(),
        _ => {
            return Err(VmError::TypeError {
                operation: "mean".to_string(),
                expected: "Vector or Tensor".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    if count == 0 {
        return Err(VmError::Runtime(
            "mean() requires a non-empty collection".to_string(),
        ));
    }

    let sum_result = vm_sum(_vm, args)?;
    match sum_result {
        Value::Number(sum) => Ok(Value::Number(sum / count as f64)),
        Value::Complex(sum) => Ok(Value::Complex(sum / Complex::from_real(count as f64))),
        _ => Err(VmError::Runtime(
            "sum() returned non-numeric value".to_string(),
        )),
    }
}

/// Calculate standard deviation
pub fn vm_std(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "std() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read();
            if vec.len() < 2 {
                return Err(VmError::Runtime(
                    "std() requires a vector with at least 2 elements".to_string(),
                ));
            }

            // Calculate mean
            drop(vec);
            let mean_result = vm_mean(_vm, args)?;

            // Calculate variance (sum of squared magnitudes of differences)
            let vec = rc.read();
            let mut variance_sum = 0.0;

            for val in vec.iter() {
                match (val, &mean_result) {
                    (Value::Number(n), Value::Number(mean_val)) => {
                        let diff = n - mean_val;
                        variance_sum += diff * diff;
                    }
                    (Value::Number(n), Value::Complex(mean_val)) => {
                        let diff = Complex::from_real(*n) - *mean_val;
                        let mag = diff.magnitude();
                        variance_sum += mag * mag;
                    }
                    (Value::Complex(c), Value::Number(mean_val)) => {
                        let diff = *c - Complex::from_real(*mean_val);
                        let mag = diff.magnitude();
                        variance_sum += mag * mag;
                    }
                    (Value::Complex(c), Value::Complex(mean_val)) => {
                        let diff = *c - *mean_val;
                        let mag = diff.magnitude();
                        variance_sum += mag * mag;
                    }
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "std".to_string(),
                            expected: "numeric or complex vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }

            let count = vec.len();
            let variance = variance_sum / (count - 1) as f64;
            Ok(Value::Number(variance.sqrt()))
        }
        Value::Tensor(t) => {
            if t.size() < 2 {
                return Err(VmError::Runtime(
                    "std() requires a tensor with at least 2 elements".to_string(),
                ));
            }
            let mean_result = vm_mean(_vm, args)?;
            let mean = match mean_result {
                Value::Number(n) => n,
                _ => return Err(VmError::Runtime("mean failed".to_string())),
            };

            let mut variance_sum = 0.0;
            for val in t.data() {
                let diff = val - mean;
                variance_sum += diff * diff;
            }
            let count = t.size();
            let variance = variance_sum / (count - 1) as f64;
            Ok(Value::Number(variance.sqrt()))
        }
        Value::ComplexTensor(_) => Err(VmError::Runtime(
            "std() not yet implemented for complex tensors".to_string(),
        )),
        _ => Err(VmError::TypeError {
            operation: "std".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_types::sync::shared;

    fn setup_vm() -> VM {
        VM::new()
    }

    #[test]
    fn test_sum_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_sum(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(15.0));
    }

    #[test]
    fn test_sum_empty() {
        let vm = setup_vm();
        let vec: Vec<Value> = vec![];
        let result = vm_sum(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(0.0));
    }

    #[test]
    fn test_mean_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_mean(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(3.0));
    }

    #[test]
    fn test_std_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(2.0),
            Value::Number(4.0),
            Value::Number(4.0),
            Value::Number(4.0),
            Value::Number(5.0),
            Value::Number(5.0),
            Value::Number(7.0),
            Value::Number(9.0),
        ];
        let result = vm_std(&vm, &[Value::Vector(shared(vec))]).unwrap();
        // Expected std dev ≈ 2.138
        if let Value::Number(n) = result {
            assert!((n - 2.138).abs() < 0.01);
        } else {
            panic!("Expected Number");
        }
    }

    #[test]
    fn test_sum_complex() {
        let vm = setup_vm();
        let vec = vec![Value::Number(1.0), Value::Complex(Complex::new(0.0, 2.0))];
        let result = vm_sum(&vm, &[Value::Vector(shared(vec))]).unwrap();
        match result {
            Value::Complex(c) => {
                assert_eq!(c.re, 1.0);
                assert_eq!(c.im, 2.0);
            }
            _ => panic!("Expected Complex"),
        }
    }
}
