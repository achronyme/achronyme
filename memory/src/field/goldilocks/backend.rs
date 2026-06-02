use serde::Deserialize;

use super::arithmetic::{gl_add, gl_mul, gl_neg, gl_sub, EPSILON, P, P_MINUS_2};
use crate::{FieldBackend, PrimeId};

// ============================================================================
// FieldBackend implementation
// ============================================================================

/// Goldilocks scalar field backend (zero-sized marker type).
///
/// `Repr = u64` — the first backend with a different representation than `[u64; 4]`.
/// This validates that the `FieldBackend` abstraction truly supports heterogeneous types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoldilocksFr;

impl FieldBackend for GoldilocksFr {
    type Repr = u64;

    const PRIME_ID: PrimeId = PrimeId::Goldilocks;
    const MODULUS_BIT_SIZE: u32 = 64;
    const BYTE_SIZE: usize = 8;

    // ========================================================================
    // Constants
    // ========================================================================

    #[inline]
    fn zero() -> u64 {
        0
    }

    #[inline]
    fn one() -> u64 {
        1
    }

    // ========================================================================
    // Construction
    // ========================================================================

    fn from_u64(val: u64) -> u64 {
        // val might be ≥ p (p < u64::MAX), so reduce.
        if val >= P {
            val - P
        } else {
            val
        }
    }

    fn from_i64(val: i64) -> u64 {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            gl_neg(Self::from_u64(val.unsigned_abs()))
        }
    }

    fn from_canonical_limbs(limbs: &[u64]) -> u64 {
        let n = limbs.len().min(4);
        if n == 0 {
            return 0;
        }
        // Horner evaluation: value = Σ limbs[i] * (2^64)^i ≡ Σ limbs[i] * ε^i (mod p)
        let mut acc: u128 = 0;
        for i in (0..n).rev() {
            acc = acc * (EPSILON as u128) + (limbs[i] as u128);
            acc %= P as u128;
        }
        acc as u64
    }

    fn to_canonical_limbs(a: &u64) -> [u64; 4] {
        [*a, 0, 0, 0]
    }

    // ========================================================================
    // Arithmetic
    // ========================================================================

    #[inline]
    fn add(a: &u64, b: &u64) -> u64 {
        gl_add(*a, *b)
    }

    #[inline]
    fn sub(a: &u64, b: &u64) -> u64 {
        gl_sub(*a, *b)
    }

    #[inline]
    fn mul(a: &u64, b: &u64) -> u64 {
        gl_mul(*a, *b)
    }

    #[inline]
    fn neg(a: &u64) -> u64 {
        gl_neg(*a)
    }

    fn inv(a: &u64) -> Option<u64> {
        if *a == 0 {
            return None;
        }
        Some(Self::pow(a, &P_MINUS_2))
    }

    #[inline]
    fn is_zero(a: &u64) -> bool {
        *a == 0
    }

    fn pow(base: &u64, exp: &[u64; 4]) -> u64 {
        let mut result = 1u64;
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                result = gl_mul(result, result);
                let multiplied = gl_mul(result, *base);
                let flag = (exp[i] >> bit) & 1;
                result = Self::ct_select(&result, &multiplied, flag);
            }
        }
        result
    }

    #[inline]
    fn ct_select(a: &u64, b: &u64, flag: u64) -> u64 {
        let mask = 0u64.wrapping_sub(flag & 1);
        (a & !mask) | (b & mask)
    }

    // ========================================================================
    // Byte serialization
    // ========================================================================

    fn to_le_bytes(a: &u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&a.to_le_bytes());
        bytes
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<u64> {
        if bytes.len() < 32 {
            return None;
        }
        // Upper 24 bytes must be zero (value must fit in 64 bits)
        if bytes[8..32].iter().any(|&b| b != 0) {
            return None;
        }
        let val = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        if val >= P {
            return None;
        }
        Some(val)
    }

    // ========================================================================
    // String I/O
    // ========================================================================

    fn to_decimal_string(a: &u64) -> String {
        a.to_string()
    }

    fn from_decimal_str(s: &str) -> Option<u64> {
        if s.is_empty() {
            return None;
        }
        // Accumulate digit-by-digit with periodic reduction.
        // After each reduction acc < p < 2^64, so acc*10+9 < 2^68, fits in u128.
        let mut acc: u128 = 0;
        for ch in s.chars() {
            let digit = ch.to_digit(10)? as u128;
            acc = acc * 10 + digit;
            if acc >= P as u128 {
                acc %= P as u128;
            }
        }
        Some(acc as u64)
    }

    fn from_hex_str(s: &str) -> Option<u64> {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        let mut acc: u128 = 0;
        for ch in hex.chars() {
            let digit = ch.to_digit(16)? as u128;
            acc = acc * 16 + digit;
            if acc >= (1u128 << 100) {
                acc %= P as u128;
            }
        }
        Some((acc % P as u128) as u64)
    }

    fn from_binary_str(s: &str) -> Option<u64> {
        if s.is_empty() || s.len() > 256 {
            return None;
        }
        let mut acc: u128 = 0;
        for ch in s.chars() {
            let bit: u128 = match ch {
                '0' => 0,
                '1' => 1,
                _ => return None,
            };
            acc = (acc << 1) | bit;
            if acc >= (1u128 << 100) {
                acc %= P as u128;
            }
        }
        Some((acc % P as u128) as u64)
    }

    // ========================================================================
    // Modulus
    // ========================================================================

    fn modulus_le_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&P.to_le_bytes());
        bytes
    }

    // ========================================================================
    // Serde
    // ========================================================================

    fn serde_serialize<S: serde::Serializer>(a: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(a, serializer)
    }

    fn serde_deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u64, D::Error> {
        let val = u64::deserialize(deserializer)?;
        if val >= P {
            return Err(serde::de::Error::custom(
                "invalid FieldElement: value >= Goldilocks modulus",
            ));
        }
        Ok(val)
    }
}
