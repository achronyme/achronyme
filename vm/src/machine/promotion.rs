use crate::error::RuntimeError;
use memory::{
    value::{TAG_INT, TAG_NUMBER},
    Value,
};

/// Trait for type promotion operations
pub trait TypePromotion {
    fn binary_op<F>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64;
}

impl TypePromotion for super::vm::VM {
    /// Binary operation with automatic Int<->Float promotion
    /// Uses direct f64 for Number+Number to preserve IEEE754 semantics
    fn binary_op<F>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
    {
        match (left.type_tag(), right.type_tag()) {
            (TAG_NUMBER, TAG_NUMBER) => {
                let a = left.as_number().unwrap();
                let b = right.as_number().unwrap();
                Ok(Value::number(f64_op(a, b)))
            }
            // --- Integer Arithmetic (promoted to Float in generic path) ---
            (TAG_INT, TAG_INT) => {
                let a = left.as_int().unwrap();
                let b = right.as_int().unwrap();
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

            _ => Err(RuntimeError::TypeMismatch(
                "Operands must be numeric".into(),
            )),
        }
    }
}
