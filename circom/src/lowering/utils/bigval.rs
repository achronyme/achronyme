//! 256-bit two's complement integer for compile-time evaluation.
//!
//! Circom `var` computations can produce values up to 254 bits (BN254 field).
//! The standard `i64` evaluator overflows on expressions like `1 << 128`.
//! `BigVal` provides full 256-bit arithmetic with signed comparison support.

use ir_forge::types::FieldConst;

mod arithmetic;
mod bitwise;
mod comparison;
mod display;
mod field;

/// A 256-bit two's complement integer stored as 4 little-endian u64 limbs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BigVal(pub [u64; 4]);

// ---------------------------------------------------------------------------
// Constants & constructors
// ---------------------------------------------------------------------------

impl BigVal {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub fn from_i64(v: i64) -> Self {
        let fill = if v < 0 { u64::MAX } else { 0 };
        Self([v as u64, fill, fill, fill])
    }

    pub fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    /// Extract as i64 if the value fits in the signed 64-bit range.
    pub fn to_i64(self) -> Option<i64> {
        if self.is_negative() {
            // Negative: upper limbs must be all-ones, and limb[0] must have bit 63 set
            if self.0[1] == u64::MAX && self.0[2] == u64::MAX && self.0[3] == u64::MAX {
                let v = self.0[0] as i64;
                if v < 0 {
                    return Some(v);
                }
            }
            None
        } else {
            // Positive: upper limbs must be zero, and limb[0] must not have bit 63 set
            if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 && (self.0[0] as i64) >= 0 {
                Some(self.0[0] as i64)
            } else {
                None
            }
        }
    }

    /// Extract as u64 if the value is non-negative and fits.
    pub fn to_u64(self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    pub fn to_field_const(self) -> FieldConst {
        let mut bytes = [0u8; 32];
        for (i, &limb) in self.0.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        FieldConst::from_le_bytes(bytes)
    }

    pub fn from_field_const(fc: FieldConst) -> Self {
        let b = fc.bytes();
        let limb = |i: usize| u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
        Self([limb(0), limb(1), limb(2), limb(3)])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    pub fn is_negative(self) -> bool {
        (self.0[3] >> 63) != 0
    }
}

#[cfg(test)]
mod tests;
