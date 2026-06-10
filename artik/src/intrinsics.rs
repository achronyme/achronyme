//! Native intrinsic annotations for lifted big-integer functions.
//!
//! A subprogram annotated with an [`Intrinsic`] is semantically
//! equivalent (for well-formed inputs) to a known big-integer helper
//! from the circom-ecdsa `bigint_func` family. The annotation is
//! produced by the circom lift, which recognizes the function source
//! structurally before annotating; the executor uses it to run a
//! native limb implementation instead of interpreting the subprogram
//! body. The body is always still present — when the runtime
//! well-formedness guards fail (out-of-range limbs, zero leading
//! divisor digit, too-small modulus), the executor falls back to the
//! interpreted body, so observable behavior is identical on every
//! input.
//!
//! Wire format: when [`crate::header::ArtikHeader::flags`] has
//! [`FLAG_INTRINSICS`] set, an annotation section follows the body
//! region:
//!
//! ```text
//! [ count : u32 LE ]
//! per entry:
//!   [ func_id : u32 LE ][ tag : u8 ][ params : u32 LE each, per tag ]
//!     tag 1 ModInv  : n, k, ret_len
//!     tag 2 ModExp  : n, k, ret_len
//!     tag 3 Prod    : n, k, ret_len
//!     tag 4 LongDiv : n, k, m, ret_len
//! ```
//!
//! Decoders that predate the section ignore trailing bytes after the
//! body region, so annotated programs decode (and run, fully
//! interpreted) on them unchanged.

use crate::error::ArtikError;
use crate::ir::{ElemT, RegType};
use crate::program::Program;

pub mod limbs;

#[cfg(test)]
mod tests;

/// Header flag bit: an intrinsic annotation section follows the body.
pub const FLAG_INTRINSICS: u8 = 0x01;

/// Largest digit width the native limb code supports (digits must fit
/// one u64 word).
pub const MAX_DIGIT_BITS: u32 = 64;

/// Largest register count per operand. Generous for the circomlib
/// corpus (ECDSA uses k = 4) while keeping native buffers small.
pub const MAX_REGISTERS: u32 = 16;

/// Largest declared output array an annotation may claim.
pub const MAX_RET_LEN: u32 = 4096;

/// A known big-integer function the executor can run natively.
///
/// `n` = bits per register (digit width), `k` = registers per operand,
/// `m` (LongDiv) = extra dividend registers, `ret_len` = the declared
/// length of the function's returned array (circom zero-fills the
/// slots past the meaningful digits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intrinsic {
    /// `mod_inv(n, k, a, p)` — Fermat inverse `a^(p-2) mod p`, with the
    /// all-zero-input early exit. Returns `k` digits, zero-padded.
    ModInv { n: u32, k: u32, ret_len: u32 },
    /// `mod_exp(n, k, a, p, e)` — `(a mod p)^e mod p`. Returns `k`
    /// digits, zero-padded.
    ModExp { n: u32, k: u32, ret_len: u32 },
    /// `prod(n, k, a, b)` — full product in `2k` digits, zero-padded.
    Prod { n: u32, k: u32, ret_len: u32 },
    /// `long_div(n, k, m, a, b)` — euclidean quotient (`m + 1` digits)
    /// and remainder (`k` digits) of the `(m + k)`-digit `a` by the
    /// `k`-digit `b`. Returned as a row-major `[2][ret_len / 2]` flat
    /// array: row 0 quotient, row 1 remainder.
    LongDiv {
        n: u32,
        k: u32,
        m: u32,
        ret_len: u32,
    },
}

/// One annotated subprogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntrinsicAnnotation {
    pub func_id: u32,
    pub intrinsic: Intrinsic,
}

impl Intrinsic {
    /// Number of subprogram parameters the annotated callee must have,
    /// as `(scalar_params, array_params)`. Scalars always precede the
    /// arrays in the `bigint_func` signatures.
    pub fn expected_params(&self) -> (usize, usize) {
        match self {
            Self::ModInv { .. } | Self::Prod { .. } => (2, 2),
            Self::ModExp { .. } => (2, 3),
            Self::LongDiv { .. } => (3, 2),
        }
    }

    /// Declared output length the annotation claims.
    pub fn ret_len(&self) -> u32 {
        match self {
            Self::ModInv { ret_len, .. }
            | Self::ModExp { ret_len, .. }
            | Self::Prod { ret_len, .. }
            | Self::LongDiv { ret_len, .. } => *ret_len,
        }
    }

    fn bounds_ok(&self) -> bool {
        let (n, k, m, ret_len) = match *self {
            Self::ModInv { n, k, ret_len }
            | Self::ModExp { n, k, ret_len }
            | Self::Prod { n, k, ret_len } => (n, k, k, ret_len),
            Self::LongDiv { n, k, m, ret_len } => (n, k, m, ret_len),
        };
        (1..=MAX_DIGIT_BITS).contains(&n)
            && (1..=MAX_REGISTERS).contains(&k)
            && (1..=MAX_REGISTERS).contains(&m)
            && (1..=MAX_RET_LEN).contains(&ret_len)
            // The meaningful digits must fit the declared output:
            // 2k for Prod, m + 1 and k per LongDiv row, k otherwise.
            && match *self {
                Self::Prod { k, ret_len, .. } => 2 * k <= ret_len,
                Self::LongDiv { k, m, ret_len, .. } => {
                    ret_len % 2 == 0 && (m + 1).max(k + 1) <= ret_len / 2
                }
                Self::ModInv { k, ret_len, .. } | Self::ModExp { k, ret_len, .. } => k <= ret_len,
            }
    }
}

/// Encode the annotation section (excluding the header flag, which the
/// caller sets). Empty input produces no bytes.
pub fn encode_section(annotations: &[IntrinsicAnnotation], out: &mut Vec<u8>) {
    if annotations.is_empty() {
        return;
    }
    out.extend_from_slice(&(annotations.len() as u32).to_le_bytes());
    for ann in annotations {
        out.extend_from_slice(&ann.func_id.to_le_bytes());
        let (tag, params): (u8, Vec<u32>) = match ann.intrinsic {
            Intrinsic::ModInv { n, k, ret_len } => (1, vec![n, k, ret_len]),
            Intrinsic::ModExp { n, k, ret_len } => (2, vec![n, k, ret_len]),
            Intrinsic::Prod { n, k, ret_len } => (3, vec![n, k, ret_len]),
            Intrinsic::LongDiv { n, k, m, ret_len } => (4, vec![n, k, m, ret_len]),
        };
        out.push(tag);
        for p in params {
            out.extend_from_slice(&p.to_le_bytes());
        }
    }
}

/// Decode the annotation section from the bytes that follow the body
/// region. Returns the parsed annotations; structural validation
/// against the program happens in [`validate_annotations`].
pub fn decode_section(bytes: &[u8]) -> Result<Vec<IntrinsicAnnotation>, ArtikError> {
    let mut pos = 0usize;
    let take_u32 = |pos: &mut usize| -> Result<u32, ArtikError> {
        let s = bytes.get(*pos..*pos + 4).ok_or(ArtikError::UnexpectedEof {
            needed: *pos + 4,
            remaining: bytes.len().saturating_sub(*pos),
        })?;
        *pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let count = take_u32(&mut pos)? as usize;
    let mut out = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let func_id = take_u32(&mut pos)?;
        let tag = *bytes.get(pos).ok_or(ArtikError::UnexpectedEof {
            needed: pos + 1,
            remaining: 0,
        })?;
        pos += 1;
        let intrinsic = match tag {
            1..=3 => {
                let n = take_u32(&mut pos)?;
                let k = take_u32(&mut pos)?;
                let ret_len = take_u32(&mut pos)?;
                match tag {
                    1 => Intrinsic::ModInv { n, k, ret_len },
                    2 => Intrinsic::ModExp { n, k, ret_len },
                    _ => Intrinsic::Prod { n, k, ret_len },
                }
            }
            4 => {
                let n = take_u32(&mut pos)?;
                let k = take_u32(&mut pos)?;
                let m = take_u32(&mut pos)?;
                let ret_len = take_u32(&mut pos)?;
                Intrinsic::LongDiv { n, k, m, ret_len }
            }
            other => return Err(ArtikError::UnknownIntrinsicTag(other)),
        };
        out.push(IntrinsicAnnotation { func_id, intrinsic });
    }
    Ok(out)
}

/// Structural validation of decoded annotations against the program:
/// known bounds, a real non-entry subprogram, and a parameter/return
/// signature matching the intrinsic's shape (scalars first, then field
/// arrays, one field-array return). A failed check rejects the
/// bytecode — an annotation that does not fit its subprogram is
/// malformed input, not a fallback case.
pub fn validate_annotations(prog: &Program) -> Result<(), ArtikError> {
    for ann in &prog.intrinsics {
        if !ann.intrinsic.bounds_ok() {
            return Err(ArtikError::BadIntrinsicAnnotation {
                func_id: ann.func_id,
            });
        }
        let idx = ann.func_id as usize;
        if idx == prog.entry || idx >= prog.subprograms.len() {
            return Err(ArtikError::BadIntrinsicAnnotation {
                func_id: ann.func_id,
            });
        }
        let sub = &prog.subprograms[idx];
        let (n_scalar, n_array) = ann.intrinsic.expected_params();
        if sub.params.len() != n_scalar + n_array
            || sub.returns.len() != 1
            || sub.returns[0] != RegType::Array(ElemT::Field)
        {
            return Err(ArtikError::BadIntrinsicAnnotation {
                func_id: ann.func_id,
            });
        }
        let scalars_ok = sub.params[..n_scalar]
            .iter()
            .all(|p| matches!(p, RegType::Field | RegType::Int(_)));
        let arrays_ok = sub.params[n_scalar..]
            .iter()
            .all(|p| *p == RegType::Array(ElemT::Field));
        if !scalars_ok || !arrays_ok {
            return Err(ArtikError::BadIntrinsicAnnotation {
                func_id: ann.func_id,
            });
        }
    }
    Ok(())
}
