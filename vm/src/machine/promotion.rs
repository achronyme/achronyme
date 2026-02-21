use crate::error::RuntimeError;
use memory::{
    value::{TAG_FIELD, TAG_INT, TAG_NUMBER},
    FieldElement, Value,
};

/// Trait for type promotion operations
pub trait TypePromotion {
    fn binary_op<F, G>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
        field_op: G,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
        G: Fn(&FieldElement, &FieldElement) -> Result<FieldElement, RuntimeError>;
}

impl TypePromotion for super::vm::VM {
    /// Binary operation with automatic Int<->Float and Int<->Field promotion
    fn binary_op<F, G>(
        &mut self,
        left: Value,
        right: Value,
        f64_op: F,
        field_op: G,
    ) -> Result<Value, RuntimeError>
    where
        F: Fn(f64, f64) -> f64,
        G: Fn(&FieldElement, &FieldElement) -> Result<FieldElement, RuntimeError>,
    {
        match (left.type_tag(), right.type_tag()) {
            (TAG_NUMBER, TAG_NUMBER) => {
                let a = left.as_number().unwrap();
                let b = right.as_number().unwrap();
                Ok(Value::number(f64_op(a, b)))
            }
            (TAG_INT, TAG_INT) => {
                let a = left.as_int().unwrap();
                let b = right.as_int().unwrap();
                Ok(Value::number(f64_op(a as f64, b as f64)))
            }
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

            // --- Field + Field ---
            (TAG_FIELD, TAG_FIELD) => {
                let ha = left.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let hb = right.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fa = *self.heap.get_field(ha).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let fb = *self.heap.get_field(hb).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let result = field_op(&fa, &fb)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            // --- Int + Field / Field + Int (promote Int to Field) ---
            (TAG_INT, TAG_FIELD) => {
                let a = FieldElement::from_i64(left.as_int().unwrap() as i64);
                let hb = right.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fb = *self.heap.get_field(hb).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let result = field_op(&a, &fb)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }
            (TAG_FIELD, TAG_INT) => {
                let ha = left.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fa = *self.heap.get_field(ha).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let b = FieldElement::from_i64(right.as_int().unwrap() as i64);
                let result = field_op(&fa, &b)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            // --- Float + Field / Field + Float → Error (non-deterministic) ---
            (TAG_NUMBER, TAG_FIELD) | (TAG_FIELD, TAG_NUMBER) => {
                Err(RuntimeError::TypeMismatch(
                    "Cannot mix Float and Field (non-deterministic)".into(),
                ))
            }

            _ => Err(RuntimeError::TypeMismatch(
                "Operands must be numeric".into(),
            )),
        }
    }
}
