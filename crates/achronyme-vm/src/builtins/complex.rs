//! Complex number functions
//!
//! This module provides complex number operations for the VM:
//! - complex: Create a complex number from real and imaginary parts
//! - real: Extract real part
//! - imag: Extract imaginary part
//! - conj: Complex conjugate
//! - arg: Argument (phase angle)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use num_complex::Complex64;

/// Create a complex number from real and imaginary parts
pub fn vm_complex(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }

    match (&args[0], &args[1]) {
        (Value::Number(re), Value::Number(im)) => {
            Ok(Value::Complex(Complex64::new(*re, *im)))
        }
        _ => Err(VmError::TypeError {
            operation: "complex".to_string(),
            expected: "two Numbers".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Extract real part of a number or complex number
pub fn vm_real(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(*n)),
        Value::Complex(c) => Ok(Value::Number(c.re)),
        Value::Vector(vec) => {
            let mut real_parts = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => real_parts.push(Value::Number(*n)),
                    Value::Complex(c) => real_parts.push(Value::Number(c.re)),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "real".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(real_parts))
        }
        _ => Err(VmError::TypeError {
            operation: "real".to_string(),
            expected: "Number, Complex, or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Extract imaginary part of a number or complex number
pub fn vm_imag(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Number(_) => Ok(Value::Number(0.0)),
        Value::Complex(c) => Ok(Value::Number(c.im)),
        Value::Vector(vec) => {
            let mut imag_parts = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(_) => imag_parts.push(Value::Number(0.0)),
                    Value::Complex(c) => imag_parts.push(Value::Number(c.im)),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "imag".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(imag_parts))
        }
        _ => Err(VmError::TypeError {
            operation: "imag".to_string(),
            expected: "Number, Complex, or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate complex conjugate
pub fn vm_conj(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(*n)),
        Value::Complex(c) => Ok(Value::Complex(c.conj())),
        Value::Vector(vec) => {
            let mut conjugates = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => conjugates.push(Value::Number(*n)),
                    Value::Complex(c) => conjugates.push(Value::Complex(c.conj())),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "conj".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(conjugates))
        }
        _ => Err(VmError::TypeError {
            operation: "conj".to_string(),
            expected: "Number, Complex, or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate argument (phase angle) of a complex number
pub fn vm_arg(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }

    match &args[0] {
        Value::Number(n) => {
            // For real numbers: arg(x) = 0 if x >= 0, π if x < 0
            if *n >= 0.0 {
                Ok(Value::Number(0.0))
            } else {
                Ok(Value::Number(std::f64::consts::PI))
            }
        }
        Value::Complex(c) => Ok(Value::Number(c.arg())),
        _ => Err(VmError::TypeError {
            operation: "arg".to_string(),
            expected: "Number or Complex".to_string(),
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
    fn test_complex_basic() {
        let mut vm = setup_vm();
        let result = vm_complex(&mut vm, &[Value::Number(3.0), Value::Number(4.0)]).unwrap();
        match result {
            Value::Complex(c) => {
                assert_eq!(c.re, 3.0);
                assert_eq!(c.im, 4.0);
            }
            _ => panic!("Expected Complex"),
        }
    }

    #[test]
    fn test_real_number() {
        let mut vm = setup_vm();
        let result = vm_real(&mut vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Number(42.0));
    }

    #[test]
    fn test_real_complex() {
        let mut vm = setup_vm();
        let c = Complex64::new(3.0, 4.0);
        let result = vm_real(&mut vm, &[Value::Complex(c)]).unwrap();
        assert_eq!(result, Value::Number(3.0));
    }

    #[test]
    fn test_imag_number() {
        let mut vm = setup_vm();
        let result = vm_imag(&mut vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Number(0.0));
    }

    #[test]
    fn test_imag_complex() {
        let mut vm = setup_vm();
        let c = Complex64::new(3.0, 4.0);
        let result = vm_imag(&mut vm, &[Value::Complex(c)]).unwrap();
        assert_eq!(result, Value::Number(4.0));
    }

    #[test]
    fn test_conj_number() {
        let mut vm = setup_vm();
        let result = vm_conj(&mut vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Number(42.0));
    }

    #[test]
    fn test_conj_complex() {
        let mut vm = setup_vm();
        let c = Complex64::new(3.0, 4.0);
        let result = vm_conj(&mut vm, &[Value::Complex(c)]).unwrap();
        match result {
            Value::Complex(conj) => {
                assert_eq!(conj.re, 3.0);
                assert_eq!(conj.im, -4.0);
            }
            _ => panic!("Expected Complex"),
        }
    }

    #[test]
    fn test_arg_positive() {
        let mut vm = setup_vm();
        let result = vm_arg(&mut vm, &[Value::Number(5.0)]).unwrap();
        assert_eq!(result, Value::Number(0.0));
    }

    #[test]
    fn test_arg_negative() {
        let mut vm = setup_vm();
        let result = vm_arg(&mut vm, &[Value::Number(-5.0)]).unwrap();
        assert_eq!(result, Value::Number(std::f64::consts::PI));
    }

    #[test]
    fn test_arg_complex() {
        let mut vm = setup_vm();
        let c = Complex64::new(1.0, 1.0);
        let result = vm_arg(&mut vm, &[Value::Complex(c)]).unwrap();
        // arg(1+i) = π/4 ≈ 0.7854
        if let Value::Number(n) = result {
            assert!((n - std::f64::consts::FRAC_PI_4).abs() < 0.001);
        } else {
            panic!("Expected Number");
        }
    }
}
