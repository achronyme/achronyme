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
use achronyme_types::complex::Complex;
use std::cell::RefCell;
use std::rc::Rc;

/// Create a complex number from real and imaginary parts
pub fn vm_complex(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "complex() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Number(re), Value::Number(im)) => {
            Ok(Value::Complex(Complex::new(*re, *im)))
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
        return Err(VmError::Runtime(format!(
            "real() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(*n)),
        Value::Complex(c) => Ok(Value::Number(c.re)),
        Value::Vector(rc) => {
            let vec = rc.borrow();
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
            Ok(Value::Vector(Rc::new(RefCell::new(real_parts))))
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
        return Err(VmError::Runtime(format!(
            "imag() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(_) => Ok(Value::Number(0.0)),
        Value::Complex(c) => Ok(Value::Number(c.im)),
        Value::Vector(rc) => {
            let vec = rc.borrow();
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
            Ok(Value::Vector(Rc::new(RefCell::new(imag_parts))))
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
        return Err(VmError::Runtime(format!(
            "conj() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(*n)),
        Value::Complex(c) => Ok(Value::Complex(c.conjugate())),
        Value::Vector(rc) => {
            let vec = rc.borrow();
            let mut conjugates = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => conjugates.push(Value::Number(*n)),
                    Value::Complex(c) => conjugates.push(Value::Complex(c.conjugate())),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "conj".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(Rc::new(RefCell::new(conjugates))))
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
        return Err(VmError::Runtime(format!(
            "arg() expects 1 argument, got {}",
            args.len()
        )));
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
        Value::Complex(c) => Ok(Value::Number(c.phase())),
        _ => Err(VmError::TypeError {
            operation: "arg".to_string(),
            expected: "Number or Complex".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// magnitude(z) -> Number
///
/// Returns the magnitude (absolute value) of a complex number or real number.
/// Also known as modulus or norm.
///
/// # Examples
/// ```achronyme
/// magnitude(complex(3, 4))  // 5.0
/// magnitude(5)              // 5.0
/// ```
pub fn vm_magnitude(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "magnitude() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(n.abs())),
        Value::Complex(c) => Ok(Value::Number(c.magnitude())),
        _ => Err(VmError::TypeError {
            operation: "magnitude".to_string(),
            expected: "Number or Complex".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// phase(z) -> Number
///
/// Returns the phase (argument) of a complex number in radians.
/// For real numbers: 0 if x >= 0, π if x < 0.
///
/// # Examples
/// ```achronyme
/// phase(complex(1, 1))  // π/4 ≈ 0.7854
/// phase(-1)             // π ≈ 3.1416
/// ```
pub fn vm_phase(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "phase() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            if *n >= 0.0 {
                Ok(Value::Number(0.0))
            } else {
                Ok(Value::Number(std::f64::consts::PI))
            }
        }
        Value::Complex(c) => Ok(Value::Number(c.phase())),
        _ => Err(VmError::TypeError {
            operation: "phase".to_string(),
            expected: "Number or Complex".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// polar(r, theta) -> Complex
///
/// Creates a complex number from polar coordinates.
/// r is the magnitude, theta is the phase in radians.
///
/// # Examples
/// ```achronyme
/// polar(1, pi/4)  // complex(0.7071, 0.7071) ≈ 1∠45°
/// polar(5, 0)     // complex(5, 0)
/// ```
pub fn vm_polar(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "polar() expects 2 arguments (r, theta), got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Number(r), Value::Number(theta)) => {
            let re = r * theta.cos();
            let im = r * theta.sin();
            Ok(Value::Complex(Complex::new(re, im)))
        }
        _ => Err(VmError::TypeError {
            operation: "polar".to_string(),
            expected: "two Numbers (r, theta)".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// to_polar(z) -> Vector
///
/// Converts a complex number to polar form [r, theta].
/// Returns a vector with magnitude and phase.
///
/// # Examples
/// ```achronyme
/// to_polar(complex(1, 1))   // [1.4142, 0.7854] ≈ [√2, π/4]
/// to_polar(complex(3, 4))   // [5, 0.9273]
/// ```
pub fn vm_to_polar(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "to_polar() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let r = n.abs();
            let theta = if *n >= 0.0 { 0.0 } else { std::f64::consts::PI };
            Ok(Value::Vector(Rc::new(RefCell::new(vec![
                Value::Number(r),
                Value::Number(theta),
            ]))))
        }
        Value::Complex(c) => {
            let r = c.magnitude();
            let theta = c.phase();
            Ok(Value::Vector(Rc::new(RefCell::new(vec![
                Value::Number(r),
                Value::Number(theta),
            ]))))
        }
        _ => Err(VmError::TypeError {
            operation: "to_polar".to_string(),
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
        let c = Complex::new(3.0, 4.0);
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
        let c = Complex::new(3.0, 4.0);
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
        let c = Complex::new(3.0, 4.0);
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
        let c = Complex::new(1.0, 1.0);
        let result = vm_arg(&mut vm, &[Value::Complex(c)]).unwrap();
        // arg(1+i) = π/4 ≈ 0.7854
        if let Value::Number(n) = result {
            assert!((n - std::f64::consts::FRAC_PI_4).abs() < 0.001);
        } else {
            panic!("Expected Number");
        }
    }
}
