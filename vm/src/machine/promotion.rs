use crate::error::RuntimeError;
use memory::{
    value::{TAG_BIGINT, TAG_FIELD, TAG_INT},
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
    /// Binary operation on Field values. Int+Field mixing is a type error.
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
            // Field + Field
            (TAG_FIELD, TAG_FIELD) => {
                let ha = left
                    .as_handle()
                    .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let hb = right
                    .as_handle()
                    .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
                let fa = *self
                    .heap
                    .get_field(ha)
                    .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let fb = *self
                    .heap
                    .get_field(hb)
                    .ok_or(RuntimeError::SystemError("Field missing".into()))?;
                let result = field_op(&fa, &fb)?;
                let handle = self.heap.alloc_field(result);
                Ok(Value::field(handle))
            }

            // Int + Field / Field + Int → type error
            (TAG_INT, TAG_FIELD) | (TAG_FIELD, TAG_INT) => Err(RuntimeError::TypeMismatch(
                "Cannot mix Int and Field in arithmetic; use 0p prefix for field literals".into(),
            )),

            // BigInt + Int / Int + BigInt → type error
            (TAG_BIGINT, TAG_INT) | (TAG_INT, TAG_BIGINT) => Err(RuntimeError::TypeMismatch(
                "Cannot mix Int and BigInt in arithmetic".into(),
            )),

            // BigInt + Field / Field + BigInt → type error
            (TAG_BIGINT, TAG_FIELD) | (TAG_FIELD, TAG_BIGINT) => Err(RuntimeError::TypeMismatch(
                "Cannot mix Field and BigInt in arithmetic".into(),
            )),

            _ => Err(RuntimeError::TypeMismatch(
                "Operands must be numeric".into(),
            )),
        }
    }
}
