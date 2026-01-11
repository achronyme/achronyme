use crate::error::RuntimeError;
use memory::{
    value::{TAG_COMPLEX, TAG_INT, TAG_NUMBER},
    Value,
};
use num_complex::Complex64;

/// Trait for type promotion operations
pub trait TypePromotion {
    fn binary_op<F, G>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
        complex_op: G,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
        G: Fn(Complex64, Complex64) -> Complex64;
}

impl TypePromotion for super::vm::VM {
    /// Binary operation with automatic Real<->Complex promotion
    /// Uses direct f64 for Number+Number to preserve IEEE754 semantics
    fn binary_op<F, G>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
        complex_op: G,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
        G: Fn(Complex64, Complex64) -> Complex64,
    {
        match (left.type_tag(), right.type_tag()) {
            (TAG_NUMBER, TAG_NUMBER) => {
                let a = left.as_number().unwrap();
                let b = right.as_number().unwrap();
                Ok(Value::number(f64_op(a, b)))
            }
            // --- Integer Arithmetic (Wrapping) ---
            (TAG_INT, TAG_INT) => {
                let a = left.as_int().unwrap();
                let b = right.as_int().unwrap();
                // We don't have the operator here easily to check for Division.
                // However, since binary_op is generic over closures, we can't easily dispatch to wrapping_div.
                // WE NEED A REFACTOR: TypePromotion trait relies on f64/Complex64 closures.
                // BUT, to support Integers without rewriting call-sites, we will try to infer operation?
                // NO, that's impossible.
                
                // STRATEGY ADJUSTMENT:
                // We will perform promotion to Float for generic binary_op calls that pass float closures.
                // WAIT, this defeats the purpose of TAG_INT speed!
                
                // BUT look at arithmetic.rs:
                // It calls `self.binary_op(vb, vc, |x, y| x + y, ...)`
                // The closures are hardcoded f64 additions.
                
                // To support Ints properly, we must promote to float HERE if the specific Int op isn't handled specially in arithmetic.rs.
                // OR checking if we can cast closures. We can't.
                
                // CORRECT APPROACH FOR THIS FILE:
                // `binary_op` is designed for floating/complex promotion.
                // For pure Integer arithmetic, `arithmetic.rs` should handle (TAG_INT, TAG_INT) *before* calling `binary_op`.
                // However, as a fallback (and for mixed types), we promote Int to Float here.
                
                Ok(Value::number(f64_op(a as f64, b as f64)))
            }
            
            // --- Mixed Int/Float ---
            (TAG_INT, TAG_NUMBER) => {
                 let a = left.as_int().unwrap() as f64;
                 let b = right.as_number().unwrap();
                 Ok(Value::number(f64_op(a, b)))
            }
            (TAG_NUMBER, TAG_INT) => {
                 let a = left.as_number().unwrap();
                 let b = right.as_int().unwrap() as f64;
                 Ok(Value::number(f64_op(a, b)))
            }

            // --- Mixed Int/Complex ---
            (TAG_INT, TAG_COMPLEX) => {
                let a = left.as_int().unwrap() as f64;
                let idx = right.as_handle().unwrap();
                let cb = self
                    .heap
                    .get_complex(idx)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let ca = Complex64::new(a, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            (TAG_COMPLEX, TAG_INT) => {
                let idx = left.as_handle().unwrap();
                let ca = self
                    .heap
                    .get_complex(idx)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let b = right.as_int().unwrap() as f64;
                let cb = Complex64::new(b, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }

            // --- Complex/Number Mixed (Existing) ---
            (TAG_NUMBER, TAG_COMPLEX) => {
                let a = left.as_number().unwrap();
                let idx = right.as_handle().unwrap();
                let cb = self
                    .heap
                    .get_complex(idx)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let ca = Complex64::new(a, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            (TAG_COMPLEX, TAG_NUMBER) => {
                let idx = left.as_handle().unwrap();
                let ca = self
                    .heap
                    .get_complex(idx)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let b = right.as_number().unwrap();
                let cb = Complex64::new(b, 0.0);
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            (TAG_COMPLEX, TAG_COMPLEX) => {
                let idx_a = left.as_handle().unwrap();
                let idx_b = right.as_handle().unwrap();
                let ca = self
                    .heap
                    .get_complex(idx_a)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let cb = self
                    .heap
                    .get_complex(idx_b)
                    .ok_or(RuntimeError::InvalidOperand)?;
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            _ => Err(RuntimeError::TypeMismatch(
                "Operands must be numeric".into(),
            )),
        }
    }
}
