//! Native execution of intrinsic-annotated subprograms.
//!
//! When a `Call` targets a subprogram carrying an
//! [`crate::intrinsics::Intrinsic`] annotation, the executor first
//! offers the call to [`try_native`]. The function marshals the
//! caller's argument registers into digit vectors, applies the
//! intrinsic's well-formedness guards, and — when they hold — computes
//! the result with the exact limb math in [`crate::intrinsics::limbs`]
//! and writes the output array straight into the caller's return
//! register. When any guard declines (`Ok(false)`), the caller falls
//! through to the ordinary interpreted `Call`, so observable behavior
//! is identical on every input; only the wall-clock changes.

use memory::field::{FieldBackend, FieldElement};

use crate::error::ArtikError;
use crate::intrinsics::{limbs, Intrinsic};
use crate::program::Program;

use super::state::{ArrayBuf, Cell, State};
use super::MAX_ARRAY_MEMORY_CELLS;

/// Attempt to run `callee` natively. Returns `Ok(true)` when the call
/// was fully handled (result written to the caller's return register),
/// `Ok(false)` when the executor should interpret the body instead.
pub(super) fn try_native<F: FieldBackend>(
    prog: &Program,
    callee: u32,
    args: &[u32],
    rets: &[u32],
    state: &mut State<F>,
) -> Result<bool, ArtikError> {
    let Some(ann) = prog.intrinsics.iter().find(|a| a.func_id == callee) else {
        return Ok(false);
    };
    let intrinsic = ann.intrinsic;
    let (n_scalar, n_array) = intrinsic.expected_params();
    if args.len() != n_scalar + n_array || rets.len() != 1 {
        return Ok(false);
    }

    // Marshal the array arguments (they follow the scalars) into digit
    // vectors. Any element that does not fit a single u64 word makes
    // the input out of range for the native path.
    let mut digit_args: Vec<Vec<u64>> = Vec::with_capacity(n_array);
    for arg in &args[n_scalar..] {
        let handle = state.read_array(*arg)?;
        let Some(ArrayBuf::Field(elems)) = state.arrays.get(handle as usize) else {
            return Ok(false);
        };
        let mut digits = Vec::with_capacity(elems.len());
        for fe in elems {
            let limbs = fe.to_canonical();
            if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
                return Ok(false);
            }
            digits.push(limbs[0]);
        }
        digit_args.push(digits);
    }

    // Meaningful output digits, in output-array order. `None` from the
    // limb math means a reference precondition does not hold — decline
    // and let the interpreter run the body.
    let ret_len = intrinsic.ret_len() as usize;
    let mut out = vec![0u64; ret_len];
    match intrinsic {
        Intrinsic::ModInv { n, k, .. } => {
            let Some(digits) = limbs::modinv_digits(n, k, &digit_args[0], &digit_args[1]) else {
                return Ok(false);
            };
            out[..digits.len()].copy_from_slice(&digits);
        }
        Intrinsic::ModExp { n, k, .. } => {
            let Some(digits) =
                limbs::modexp_digits(n, k, &digit_args[0], &digit_args[1], &digit_args[2])
            else {
                return Ok(false);
            };
            out[..digits.len()].copy_from_slice(&digits);
        }
        Intrinsic::Prod { n, k, .. } => {
            let Some(digits) = limbs::prod_digits(n, k, &digit_args[0], &digit_args[1]) else {
                return Ok(false);
            };
            out[..digits.len()].copy_from_slice(&digits);
        }
        Intrinsic::LongDiv { n, k, m, .. } => {
            let Some((q, r)) = limbs::longdiv_digits(n, k, m, &digit_args[0], &digit_args[1])
            else {
                return Ok(false);
            };
            // Row-major [2][ret_len / 2]: row 0 quotient, row 1
            // remainder, both zero-padded like the reference's
            // zero-initialized output array.
            let row = ret_len / 2;
            out[..q.len()].copy_from_slice(&q);
            out[row..row + r.len()].copy_from_slice(&r);
        }
    }

    // Allocate the output array under the same cumulative budget the
    // interpreted body's `AllocArray` would have paid.
    let prospective = state.array_cells_used.saturating_add(ret_len as u64);
    if prospective > MAX_ARRAY_MEMORY_CELLS {
        return Err(ArtikError::ArrayMemoryExceeded {
            cells: prospective,
            max: MAX_ARRAY_MEMORY_CELLS,
        });
    }
    state.array_cells_used = prospective;

    let elems: Vec<FieldElement<F>> = out.into_iter().map(FieldElement::<F>::from_u64).collect();
    let handle = state.arrays.len() as u32;
    state.arrays.push(ArrayBuf::Field(elems));
    state.write(rets[0], Cell::Array(handle))?;
    Ok(true)
}
