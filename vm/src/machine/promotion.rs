use crate::error::RuntimeError;
use memory::{
    value::{TAG_FIELD, TAG_INT},
    FieldElement, Value,
};

/// Trait for type promotion operations
pub trait TypePromotion {
    fn binary_op<G>(
        &mut self,
        left: Value,
        right: Value,
        field_op: G,
    ) -> Result<Value, RuntimeError>
    where
        G: Fn(&FieldElement, &FieldElement) -> Result<FieldElement, RuntimeError>;
}

impl TypePromotion for super::vm::VM {
    /// Binary operation with automatic Int→Field promotion
    fn binary_op<G>(
        &mut self,
        left: Value,
        right: Value,
        field_op: G,
    ) -> Result<Value, RuntimeError>
    where
        G: Fn(&FieldElement, &FieldElement) -> Result<FieldElement, RuntimeError>,
    {
        match (left.tag(), right.tag()) {
            // Int + Int → promote both to Field
            (TAG_INT, TAG_INT) => {
                let a = FieldElement::from_i64(left.as_int().unwrap());
                let b = FieldElement::from_i64(right.as_int().unwrap());
                let result = field_op(&a, &b)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            // Field + Field
            (TAG_FIELD, TAG_FIELD) => {
                let ha = left.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let hb = right.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fa = *self.heap.get_field(ha).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let fb = *self.heap.get_field(hb).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let result = field_op(&fa, &fb)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            // Int + Field / Field + Int (promote Int to Field)
            (TAG_INT, TAG_FIELD) => {
                let a = FieldElement::from_i64(left.as_int().unwrap());
                let hb = right.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fb = *self.heap.get_field(hb).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let result = field_op(&a, &fb)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }
            (TAG_FIELD, TAG_INT) => {
                let ha = left.as_handle().ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fa = *self.heap.get_field(ha).ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let b = FieldElement::from_i64(right.as_int().unwrap());
                let result = field_op(&fa, &b)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            _ => Err(RuntimeError::TypeMismatch(
                "Operands must be numeric".into(),
            )),
        }
    }
}
