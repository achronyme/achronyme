//! Math utility natives: abs, min, max, pow.

use ach_macros::{ach_module, ach_native};
use vm::error::RuntimeError;

#[ach_module(name = "math")]
pub mod math_impl {
    use super::*;

    /// `abs(n)` → absolute value of an integer.
    #[ach_native(name = "abs", arity = 1)]
    pub fn native_abs(n: i64) -> i64 {
        n.abs()
    }

    /// `min(a, b)` → the smaller of two integers.
    #[ach_native(name = "min", arity = 2)]
    pub fn native_min(a: i64, b: i64) -> i64 {
        a.min(b)
    }

    /// `max(a, b)` → the larger of two integers.
    #[ach_native(name = "max", arity = 2)]
    pub fn native_max(a: i64, b: i64) -> i64 {
        a.max(b)
    }

    /// `pow(base, exp)` → integer exponentiation (exp must be non-negative).
    #[ach_native(name = "pow", arity = 2)]
    pub fn native_pow(base: i64, exp: i64) -> Result<i64, RuntimeError> {
        if exp < 0 {
            return Err(RuntimeError::TypeMismatch(
                "pow() exponent must be non-negative".into(),
            ));
        }
        if exp > u32::MAX as i64 {
            return Err(RuntimeError::TypeMismatch(
                "pow() exponent too large".into(),
            ));
        }
        let result = (base as i128).pow(exp as u32);
        if result > i64::MAX as i128 || result < i64::MIN as i128 {
            return Err(RuntimeError::TypeMismatch(
                "pow() result overflows Int range".into(),
            ));
        }
        Ok(result as i64)
    }
}
