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
                    .ok_or_else(|| RuntimeError::type_mismatch("bad field handle"))?;
                let hb = right
                    .as_handle()
                    .ok_or_else(|| RuntimeError::type_mismatch("bad field handle"))?;
                let fa = *self
                    .heap
                    .get_field(ha)
                    .ok_or(RuntimeError::stale_heap("Field", "binary_op"))?;
                let fb = *self
                    .heap
                    .get_field(hb)
                    .ok_or(RuntimeError::stale_heap("Field", "binary_op"))?;
                let result = field_op(&fa, &fb)?;
                let handle = self.heap.alloc_field(result)?;
                Ok(Value::field(handle))
            }

            // Int + Field / Field + Int → type error
            (TAG_INT, TAG_FIELD) | (TAG_FIELD, TAG_INT) => Err(RuntimeError::type_mismatch(
                "Cannot mix Int and Field in arithmetic; use 0p prefix for field literals",
            )),

            // BigInt + Int / Int + BigInt → type error
            (TAG_BIGINT, TAG_INT) | (TAG_INT, TAG_BIGINT) => Err(RuntimeError::type_mismatch(
                "Cannot mix Int and BigInt in arithmetic",
            )),

            // BigInt + Field / Field + BigInt → type error
            (TAG_BIGINT, TAG_FIELD) | (TAG_FIELD, TAG_BIGINT) => Err(RuntimeError::type_mismatch(
                "Cannot mix Field and BigInt in arithmetic",
            )),

            _ => Err(RuntimeError::type_mismatch("Operands must be numeric")),
        }
    }
}
