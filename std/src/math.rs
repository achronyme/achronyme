//! Math utility natives: abs, min, max, pow.

use memory::Value;
use vm::error::RuntimeError;
use vm::machine::VM;
use vm::module::{NativeDef, NativeModule};

pub struct MathModule;

impl NativeModule for MathModule {
    fn name(&self) -> &'static str {
        "math"
    }

    fn natives(&self) -> Vec<NativeDef> {
        vec![
            NativeDef {
                name: "abs",
                func: native_abs,
                arity: 1,
            },
            NativeDef {
                name: "min",
                func: native_min,
                arity: 2,
            },
            NativeDef {
                name: "max",
                func: native_max,
                arity: 2,
            },
            NativeDef {
                name: "pow",
                func: native_pow,
                arity: 2,
            },
        ]
    }
}

/// `abs(n)` → absolute value of an integer.
pub fn native_abs(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "abs() takes exactly 1 argument".into(),
        ));
    }
    let n = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("abs() expects an Int".into()))?;
    Ok(Value::int(n.abs()))
}

/// `min(a, b)` → the smaller of two integers.
pub fn native_min(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "min() takes exactly 2 arguments".into(),
        ));
    }
    let a = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("min() expects Int arguments".into()))?;
    let b = args[1]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("min() expects Int arguments".into()))?;
    Ok(Value::int(a.min(b)))
}

/// `max(a, b)` → the larger of two integers.
pub fn native_max(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "max() takes exactly 2 arguments".into(),
        ));
    }
    let a = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("max() expects Int arguments".into()))?;
    let b = args[1]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("max() expects Int arguments".into()))?;
    Ok(Value::int(a.max(b)))
}

/// `pow(base, exp)` → integer exponentiation (exp must be non-negative).
pub fn native_pow(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "pow() takes exactly 2 arguments".into(),
        ));
    }
    let base = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("pow() expects Int arguments".into()))?;
    let exp = args[1]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("pow() expects Int arguments".into()))?;
    if exp < 0 {
        return Err(RuntimeError::TypeMismatch(
            "pow() exponent must be non-negative".into(),
        ));
    }
    // Checked pow to avoid silent overflow
    let result = (base as i128).pow(exp as u32);
    if result > i64::MAX as i128 || result < i64::MIN as i128 {
        return Err(RuntimeError::TypeMismatch(
            "pow() result overflows Int range".into(),
        ));
    }
    Ok(Value::int(result as i64))
}
