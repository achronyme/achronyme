//! Fixed-width unsigned big integers: 256-bit (4 limbs) and 512-bit (8 limbs).
//!
//! Non-modular arithmetic with overflow/underflow errors.
//! VM-only — not supported in circuit mode.

use std::fmt;

mod arithmetic;
mod bitwise;
mod conversion;
mod parse;
mod traits;

/// Width of a BigInt: 256 or 512 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BigIntWidth {
    W256,
    W512,
}

impl BigIntWidth {
    /// Number of 64-bit limbs for this width.
    #[inline]
    pub fn num_limbs(self) -> usize {
        match self {
            BigIntWidth::W256 => 4,
            BigIntWidth::W512 => 8,
        }
    }

    /// Number of bits for this width.
    #[inline]
    pub fn num_bits(self) -> usize {
        match self {
            BigIntWidth::W256 => 256,
            BigIntWidth::W512 => 512,
        }
    }
}

/// Errors from BigInt arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BigIntError {
    Overflow,
    Underflow,
    DivisionByZero,
    WidthMismatch,
}

impl fmt::Display for BigIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BigIntError::Overflow => write!(f, "BigInt overflow"),
            BigIntError::Underflow => write!(f, "BigInt underflow"),
            BigIntError::DivisionByZero => write!(f, "BigInt division by zero"),
            BigIntError::WidthMismatch => write!(f, "BigInt width mismatch"),
        }
    }
}

impl std::error::Error for BigIntError {}

/// Fixed-width unsigned big integer.
///
/// Limbs are stored in little-endian order (limbs[0] is least significant).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigInt {
    limbs: Vec<u64>,
    width: BigIntWidth,
}

// ============================================================================
// BigInt public API
// ============================================================================

impl BigInt {
    /// Construct from raw limbs (LE order). The limbs length must match the width.
    pub fn from_limbs(limbs: Vec<u64>, width: BigIntWidth) -> Option<Self> {
        if limbs.len() != width.num_limbs() {
            return None;
        }
        Some(Self { limbs, width })
    }

    /// Create a zero BigInt of the given width.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let z = BigInt::zero(BigIntWidth::W256);
    /// assert!(z.is_zero());
    /// assert_eq!(z.width(), BigIntWidth::W256);
    /// ```
    pub fn zero(width: BigIntWidth) -> Self {
        Self {
            limbs: vec![0u64; width.num_limbs()],
            width,
        }
    }

    /// Create a BigInt with value 1.
    pub fn one(width: BigIntWidth) -> Self {
        let mut limbs = vec![0u64; width.num_limbs()];
        limbs[0] = 1;
        Self { limbs, width }
    }

    /// Create a BigInt from a u64 value.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let b = BigInt::from_u64(42, BigIntWidth::W256);
    /// assert_eq!(b.to_hex_string(), "2a");
    /// ```
    pub fn from_u64(val: u64, width: BigIntWidth) -> Self {
        let mut limbs = vec![0u64; width.num_limbs()];
        limbs[0] = val;
        Self { limbs, width }
    }

    /// Width of this BigInt.
    #[inline]
    pub fn width(&self) -> BigIntWidth {
        self.width
    }

    /// Number of 64-bit limbs.
    #[inline]
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    /// Whether this value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Get limbs slice (LE order).
    #[inline]
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    fn check_width(&self, other: &Self) -> Result<(), BigIntError> {
        if self.width != other.width {
            Err(BigIntError::WidthMismatch)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
