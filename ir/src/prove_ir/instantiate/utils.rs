//! Free helpers used across instantiator submodules.
//!
//! [`fe_to_u64`] and [`fe_to_usize`] convert a constant
//! [`FieldElement`] into a small native integer, returning a
//! [`ProveIrError::UnsupportedOperation`] when the value would
//! overflow. They are the canonical way to interpret a capture as
//! a loop bound or an array size.

use memory::{FieldBackend, FieldElement};

use ir_forge::ProveIrError;

/// Convert a FieldElement to u64, with error on overflow.
/// Only valid for "small" values that fit in a single limb.
pub(super) fn fe_to_u64<F: FieldBackend>(
    fe: &FieldElement<F>,
    context: &str,
) -> Result<u64, ProveIrError> {
    let limbs = fe.to_canonical(); // [u64; 4]
                                   // Value fits in u64 only if upper limbs are zero
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return Err(ProveIrError::UnsupportedOperation {
            description: format!(
                "capture `{context}` value is too large for a loop bound or array size"
            ),
            span: None,
        });
    }
    Ok(limbs[0])
}

/// Convert a FieldElement to usize, with error on overflow.
pub(super) fn fe_to_usize<F: FieldBackend>(
    fe: &FieldElement<F>,
    context: &str,
) -> Result<usize, ProveIrError> {
    let v = fe_to_u64(fe, context)?;
    usize::try_from(v).map_err(|_| ProveIrError::UnsupportedOperation {
        description: format!(
            "capture `{context}` value {v} is too large for an array size on this platform"
        ),
        span: None,
    })
}
