use crate::error::RuntimeError;
use memory::{Value, value::{TAG_NUMBER, TAG_COMPLEX}};
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
            (TAG_NUMBER, TAG_COMPLEX) => {
                let a = left.as_number().unwrap();
                let idx = right.as_handle().unwrap();
                let cb = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
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
                let ca = self.heap.get_complex(idx).ok_or(RuntimeError::InvalidOperand)?;
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
                let ca = self.heap.get_complex(idx_a).ok_or(RuntimeError::InvalidOperand)?;
                let cb = self.heap.get_complex(idx_b).ok_or(RuntimeError::InvalidOperand)?;
                let result = complex_op(ca, cb);
                if result.im.abs() < 1e-15 {
                    Ok(Value::number(result.re))
                } else {
                    Ok(Value::complex(self.heap.alloc_complex(result)))
                }
            }
            _ => Err(RuntimeError::TypeMismatch("Operands must be numeric".into())),
        }
    }
}
