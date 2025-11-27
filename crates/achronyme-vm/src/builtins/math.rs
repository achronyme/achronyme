//! Mathematical built-in functions
//!
//! This module provides mathematical operations including:
//! - Trigonometric: sin, cos, tan, asin, acos, atan, atan2
//! - Hyperbolic: sinh, cosh, tanh
//! - Exponential/Logarithmic: exp, ln, log, log10, log2
//! - Rounding: floor, ceil, round, trunc
//! - Other: sqrt, abs, pow, min, max, sign

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::shared;

// ============================================================================
// Helper Macros
// ============================================================================

/// Macro for unary math functions that support scalars and vectors
macro_rules! unary_math_fn {
    ($name:expr, $f:expr) => {
        |_vm: &mut VM, args: &[Value]| -> Result<Value, VmError> {
            if args.len() != 1 {
                return Err(VmError::Runtime(format!(
                    "{}() expects 1 argument, got {}",
                    $name,
                    args.len()
                )));
            }

            match &args[0] {
                Value::Number(x) => Ok(Value::Number($f(*x))),
                Value::Vector(v) => {
                    let vec_borrowed = v.read();
                    let mut result = Vec::with_capacity(vec_borrowed.len());
                    for val in vec_borrowed.iter() {
                        match val {
                            Value::Number(n) => result.push(Value::Number($f(*n))),
                            _ => {
                                return Err(VmError::TypeError {
                                    operation: $name.to_string(),
                                    expected: "Number".to_string(),
                                    got: format!("{:?}", val),
                                })
                            }
                        }
                    }
                    drop(vec_borrowed);
                    Ok(Value::Vector(shared(result)))
                }
                _ => Err(VmError::TypeError {
                    operation: $name.to_string(),
                    expected: "Number or Vector".to_string(),
                    got: format!("{:?}", args[0]),
                }),
            }
        }
    };
}

/// Macro for binary math functions
macro_rules! binary_math_fn {
    ($name:expr, $f:expr) => {
        |_vm: &mut VM, args: &[Value]| -> Result<Value, VmError> {
            if args.len() != 2 {
                return Err(VmError::Runtime(format!(
                    "{}() expects 2 arguments, got {}",
                    $name,
                    args.len()
                )));
            }

            match (&args[0], &args[1]) {
                (Value::Number(a), Value::Number(b)) => Ok(Value::Number($f(*a, *b))),
                _ => Err(VmError::TypeError {
                    operation: $name.to_string(),
                    expected: "Number, Number".to_string(),
                    got: format!("{:?}, {:?}", args[0], args[1]),
                }),
            }
        }
    };
}

// ============================================================================
// Trigonometric Functions
// ============================================================================

pub fn vm_sin() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("sin", f64::sin)
}

pub fn vm_cos() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("cos", f64::cos)
}

pub fn vm_tan() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("tan", f64::tan)
}

pub fn vm_asin() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("asin", f64::asin)
}

pub fn vm_acos() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("acos", f64::acos)
}

pub fn vm_atan() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("atan", f64::atan)
}

pub fn vm_atan2(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "atan2() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Number(y), Value::Number(x)) => Ok(Value::Number(y.atan2(*x))),
        _ => Err(VmError::TypeError {
            operation: "atan2".to_string(),
            expected: "Number, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Hyperbolic Functions
// ============================================================================

pub fn vm_sinh() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("sinh", f64::sinh)
}

pub fn vm_cosh() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("cosh", f64::cosh)
}

pub fn vm_tanh() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("tanh", f64::tanh)
}

// ============================================================================
// Exponential and Logarithmic Functions
// ============================================================================

pub fn vm_exp() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("exp", f64::exp)
}

pub fn vm_ln() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("ln", f64::ln)
}

pub fn vm_log() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    binary_math_fn!("log", |x: f64, base: f64| x.log(base))
}

pub fn vm_log10() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("log10", f64::log10)
}

pub fn vm_log2() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("log2", f64::log2)
}

// ============================================================================
// Rounding Functions
// ============================================================================

pub fn vm_floor() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("floor", f64::floor)
}

pub fn vm_ceil() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("ceil", f64::ceil)
}

pub fn vm_round() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("round", f64::round)
}

pub fn vm_trunc() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("trunc", f64::trunc)
}

// ============================================================================
// Other Math Functions
// ============================================================================

pub fn vm_sqrt() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("sqrt", f64::sqrt)
}

pub fn vm_abs() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("abs", f64::abs)
}

pub fn vm_pow() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    binary_math_fn!("pow", f64::powf)
}

pub fn vm_min(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "min() requires at least 1 argument".to_string(),
        ));
    }

    let mut min_val = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "min".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    for arg in args.iter().skip(1) {
        match arg {
            Value::Number(n) => {
                if *n < min_val {
                    min_val = *n;
                }
            }
            _ => {
                return Err(VmError::TypeError {
                    operation: "min".to_string(),
                    expected: "Number".to_string(),
                    got: format!("{:?}", arg),
                })
            }
        }
    }

    Ok(Value::Number(min_val))
}

pub fn vm_max(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "max() requires at least 1 argument".to_string(),
        ));
    }

    let mut max_val = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "max".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    for arg in args.iter().skip(1) {
        match arg {
            Value::Number(n) => {
                if *n > max_val {
                    max_val = *n;
                }
            }
            _ => {
                return Err(VmError::TypeError {
                    operation: "max".to_string(),
                    expected: "Number".to_string(),
                    got: format!("{:?}", arg),
                })
            }
        }
    }

    Ok(Value::Number(max_val))
}

pub fn vm_sign() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("sign", |x: f64| {
        if x > 0.0 {
            1.0
        } else if x < 0.0 {
            -1.0
        } else {
            0.0
        }
    })
}

pub fn vm_deg() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("deg", f64::to_degrees)
}

pub fn vm_rad() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("rad", f64::to_radians)
}

pub fn vm_cbrt() -> fn(&mut VM, &[Value]) -> Result<Value, VmError> {
    unary_math_fn!("cbrt", f64::cbrt)
}

// ============================================================================
// Constants
// ============================================================================

pub fn vm_pi(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime(format!(
            "pi() expects 0 arguments, got {}",
            args.len()
        )));
    }
    Ok(Value::Number(std::f64::consts::PI))
}

pub fn vm_e(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime(format!(
            "e() expects 0 arguments, got {}",
            args.len()
        )));
    }
    Ok(Value::Number(std::f64::consts::E))
}

// ============================================================================
// Precision Control
// ============================================================================

/// Set global precision for number formatting and rounding
pub fn vm_set_precision(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "set_precision() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let decimals = *n as i32;
            vm.set_precision(decimals);
            Ok(Value::Null)
        }
        _ => Err(VmError::TypeError {
            operation: "set_precision".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
