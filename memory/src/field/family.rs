//! Field family — coarse-grained classification of primes by canonical
//! byte width, used as a bytecode-header tag so that `.artik` / `.lysi`
//! files can declare which family of prime they target without committing
//! to a specific curve.
//!
//! ## Binary-format invariant
//!
//! This enum is `#[repr(u8)]` with **explicit, stable discriminants**.
//! Those discriminants are written directly (via `as u8`) into the
//! Artik bytecode header at byte offset 6, and into the Lysis bytecode
//! header at the same offset. Changing the order of the variants or
//! their discriminant values is a **breaking change to the bytecode
//! format** — existing `.artik` and `.lysi` files would fail to decode
//! with an `UnknownFieldFamily` error. Do not reorder.

/// Field family — primes that share the same canonical-byte width, and
/// therefore can share the same bytecode layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldFamily {
    /// 254/255-bit primes: BN254, BLS12-381 Fr. Constants up to 32 bytes.
    BnLike256 = 0,
    /// Goldilocks (2^64 - 2^32 + 1). Constants up to 8 bytes.
    Goldilocks64 = 1,
    /// Mersenne31 (2^31 - 1). Constants up to 4 bytes. Reserved for v2.
    M31_32 = 2,
}

impl FieldFamily {
    /// Decode from the single-byte on-disk representation.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::BnLike256),
            1 => Some(Self::Goldilocks64),
            2 => Some(Self::M31_32),
            _ => None,
        }
    }

    /// Maximum serialized length of a single field constant in this
    /// family. Validators reject any const-pool entry larger than this.
    pub fn max_const_bytes(self) -> usize {
        match self {
            Self::BnLike256 => 32,
            Self::Goldilocks64 => 8,
            Self::M31_32 => 4,
        }
    }
}
