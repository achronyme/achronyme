//! Goldilocks prime field (p = 2^64 - 2^32 + 1) backend — direct `u64` arithmetic.
//!
//! Unlike BN254/BLS12-381 which use Montgomery form over `[u64; 4]`, Goldilocks
//! uses plain modular arithmetic on a single `u64`. The special structure of the
//! prime (p = 2^64 - 2^32 + 1) allows fast reduction: since 2^64 ≡ 2^32 - 1 (mod p),
//! a 128-bit product can be reduced in two steps without division.

use super::backend::FieldBackend;
use super::prime_id::PrimeId;
use serde::Deserialize;

// ============================================================================
// Goldilocks Constants
// ============================================================================

/// The prime modulus: p = 2^64 - 2^32 + 1
const P: u64 = 0xFFFFFFFF00000001;

/// ε = 2^32 - 1. Key identity: 2^64 ≡ ε (mod p).
const EPSILON: u64 = 0xFFFFFFFF;

/// p - 2, for Fermat's little theorem inversion.
const P_MINUS_2: [u64; 4] = [0xFFFFFFFEFFFFFFFF, 0, 0, 0];

// ============================================================================
// Fast modular reduction
// ============================================================================

/// Reduce a u128 value modulo p using the Goldilocks identity 2^64 ≡ ε (mod p).
///
/// Two-step reduction (no division):
/// 1. x = x_hi·2^64 + x_lo ≡ x_hi·ε + x_lo (mod p)  → fits in ~96 bits
/// 2. t = t_hi·2^64 + t_lo ≡ t_hi·ε + t_lo (mod p)  → fits in ~65 bits
/// 3. One conditional subtraction of p.
///
/// Fully constant-time (branchless).
#[inline]
fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;

    // Step 1: x ≡ x_hi * ε + x_lo (mod p)
    let t: u128 = (x_hi as u128) * (EPSILON as u128) + (x_lo as u128);

    let t_lo = t as u64;
    let t_hi = (t >> 64) as u64; // ≤ 2^32

    // Step 2: t ≡ t_hi * ε + t_lo (mod p)
    // t_hi * ε ≤ 2^32 * (2^32 - 1) < 2^64, fits in u64
    let (res, carry) = t_lo.overflowing_add(t_hi.wrapping_mul(EPSILON));

    // If carry: true value = res + 2^64 ≡ res + ε (mod p).
    // When carry occurs, res < 2^64 - 2^32, so res + ε < 2^64. No overflow.
    let res = res.wrapping_add((carry as u64).wrapping_mul(EPSILON));

    // Conditional subtraction: res < 2p, so at most one subtract.
    let (r, borrow) = res.overflowing_sub(P);
    let mask = 0u64.wrapping_sub(borrow as u64);
    (res & mask) | (r & !mask)
}

// ============================================================================
// Modular arithmetic (constant-time)
// ============================================================================

/// (a + b) mod p.
#[inline]
fn gl_add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    // If carry: sum wrapped, add ε (since 2^64 ≡ ε mod p). Result < p, no further reduce.
    // If no carry: sum might be ≥ p, conditional subtract.
    let adj = sum.wrapping_add((carry as u64).wrapping_mul(EPSILON));
    let (r, borrow) = adj.overflowing_sub(P);
    let mask = 0u64.wrapping_sub(borrow as u64);
    (adj & mask) | (r & !mask)
}

/// (a - b) mod p.
#[inline]
fn gl_sub(a: u64, b: u64) -> u64 {
    let (r, borrow) = a.overflowing_sub(b);
    // If borrow: add p back.
    let mask = 0u64.wrapping_sub(borrow as u64);
    r.wrapping_add(P & mask)
}

/// (a * b) mod p.
#[inline]
fn gl_mul(a: u64, b: u64) -> u64 {
    reduce128(a as u128 * b as u128)
}

/// (-a) mod p.
#[inline]
fn gl_neg(a: u64) -> u64 {
    // Constant-time: compute p - a, then zero-mask if a was 0.
    let is_nonzero = (a | a.wrapping_neg()) >> 63;
    let mask = 0u64.wrapping_sub(is_nonzero);
    P.wrapping_sub(a) & mask
}

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldElement;

    type GlFE = FieldElement<GoldilocksFr>;

    // -- Constant verification -----------------------------------------------

    #[test]
    fn test_prime_properties() {
        // p = 2^64 - 2^32 + 1
        assert_eq!(P, (1u64 << 32).wrapping_neg().wrapping_add(1)); // -2^32 + 1 in u64 = 2^64 - 2^32 + 1
        assert_eq!(P, 0xFFFFFFFF00000001);
        assert_eq!(EPSILON, 0xFFFFFFFF);
        // 2^64 = p + ε
        assert_eq!(P.wrapping_add(EPSILON), 0); // wraps to 0, confirming 2^64 = p + ε
    }

    #[test]
    fn test_p_minus_2() {
        assert_eq!(P_MINUS_2[0], P - 2);
        assert_eq!(P_MINUS_2[1], 0);
        assert_eq!(P_MINUS_2[2], 0);
        assert_eq!(P_MINUS_2[3], 0);
    }

    // -- reduce128 -----------------------------------------------------------

    #[test]
    fn test_reduce128_basic() {
        assert_eq!(reduce128(0), 0);
        assert_eq!(reduce128(1), 1);
        assert_eq!(reduce128(42), 42);
        assert_eq!(reduce128(P as u128), 0);
        assert_eq!(reduce128(P as u128 + 1), 1);
        assert_eq!(reduce128(P as u128 * 2), 0);
        assert_eq!(reduce128(P as u128 * 2 + 7), 7);
    }

    #[test]
    fn test_reduce128_large() {
        // (p-1)^2 mod p should be 1 (since p-1 ≡ -1)
        let pm1 = (P - 1) as u128;
        assert_eq!(reduce128(pm1 * pm1), 1);

        // 2^64 mod p = ε
        assert_eq!(reduce128(1u128 << 64), EPSILON);

        // 2^96 mod p = ε^2 ... wait let me compute:
        // 2^96 = (2^64)^{3/2}... no, 2^96 = 2^64 * 2^32
        // ≡ ε * 2^32 = (2^32 - 1) * 2^32 = 2^64 - 2^32 = p - 1
        assert_eq!(reduce128(1u128 << 96), P - 1);
    }

    // -- Zero and one --------------------------------------------------------

    #[test]
    fn test_zero_and_one() {
        assert!(GoldilocksFr::is_zero(&GoldilocksFr::zero()));
        assert!(!GoldilocksFr::is_zero(&GoldilocksFr::one()));
        assert_eq!(GoldilocksFr::to_canonical_limbs(&1), [1, 0, 0, 0]);
        assert_eq!(GoldilocksFr::to_canonical_limbs(&0), [0; 4]);
    }

    // -- Construction --------------------------------------------------------

    #[test]
    fn test_from_u64_small() {
        for &val in &[0u64, 1, 2, 42, 1000] {
            assert_eq!(GoldilocksFr::from_u64(val), val);
        }
    }

    #[test]
    fn test_from_u64_near_modulus() {
        // Values >= p need reduction
        assert_eq!(GoldilocksFr::from_u64(P), 0);
        assert_eq!(GoldilocksFr::from_u64(P + 1), 1);
        assert_eq!(GoldilocksFr::from_u64(u64::MAX), u64::MAX - P);
    }

    #[test]
    fn test_from_i64_negative() {
        let neg_one = GoldilocksFr::from_i64(-1);
        assert_eq!(gl_add(neg_one, 1), 0);
        assert_eq!(neg_one, P - 1);
    }

    #[test]
    fn test_from_canonical_limbs_single() {
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[42]), 42);
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[P]), 0);
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[0, 0, 0, 0]), 0);
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[7, 0, 0, 0]), 7);
    }

    #[test]
    fn test_from_canonical_limbs_multi() {
        // [0, 1, 0, 0] = 1 * 2^64 ≡ ε (mod p)
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[0, 1, 0, 0]), EPSILON);
        // [0, 0, 1, 0] = 1 * 2^128 = (2^64)^2 ≡ ε^2 (mod p)
        let eps_sq = (EPSILON as u128 * EPSILON as u128 % P as u128) as u64;
        assert_eq!(GoldilocksFr::from_canonical_limbs(&[0, 0, 1, 0]), eps_sq);
    }

    // -- Arithmetic ----------------------------------------------------------

    #[test]
    fn test_add() {
        assert_eq!(gl_add(7, 5), 12);
        assert_eq!(gl_add(0, 0), 0);
        assert_eq!(gl_add(P - 1, 1), 0); // wrap around
        assert_eq!(gl_add(P - 1, 2), 1);
    }

    #[test]
    fn test_sub() {
        assert_eq!(gl_sub(10, 3), 7);
        assert_eq!(gl_sub(0, 0), 0);
        assert_eq!(gl_sub(0, 1), P - 1); // underflow wraps to p-1
        assert_eq!(gl_sub(3, 10), P - 7); // 3 - 10 ≡ p - 7
    }

    #[test]
    fn test_mul() {
        assert_eq!(gl_mul(6, 7), 42);
        assert_eq!(gl_mul(0, 12345), 0);
        assert_eq!(gl_mul(1, 12345), 12345);
        assert_eq!(gl_mul(P - 1, P - 1), 1); // (-1)(-1) = 1
    }

    #[test]
    fn test_neg() {
        assert_eq!(gl_neg(0), 0);
        assert_eq!(gl_neg(1), P - 1);
        assert_eq!(gl_neg(P - 1), 1);
        assert_eq!(gl_add(gl_neg(42), 42), 0);
    }

    #[test]
    fn test_inv() {
        for &val in &[1u64, 2, 7, 42, 12345, P - 1] {
            let inv = GoldilocksFr::inv(&val).unwrap();
            assert_eq!(gl_mul(val, inv), 1, "inv({val}) failed");
        }
        assert!(GoldilocksFr::inv(&0).is_none());
    }

    #[test]
    fn test_pow() {
        assert_eq!(GoldilocksFr::pow(&2, &[10, 0, 0, 0]), 1024);
        assert_eq!(GoldilocksFr::pow(&2, &[0, 0, 0, 0]), 1); // x^0 = 1
        assert_eq!(GoldilocksFr::pow(&0, &[10, 0, 0, 0]), 0); // 0^n = 0
        assert_eq!(
            GoldilocksFr::pow(&1, &[u64::MAX, u64::MAX, u64::MAX, u64::MAX]),
            1
        );
    }

    #[test]
    fn test_multiplicative_identity() {
        let a = 12345u64;
        assert_eq!(gl_mul(a, 1), a);
        assert_eq!(gl_mul(1, a), a);
    }

    #[test]
    fn test_additive_identity() {
        let a = 12345u64;
        assert_eq!(gl_add(a, 0), a);
        assert_eq!(gl_add(0, a), a);
    }

    #[test]
    fn test_distributive() {
        let a = 12345u64;
        let b = 67890u64;
        let c = 11111u64;
        // a * (b + c) = a*b + a*c
        assert_eq!(gl_mul(a, gl_add(b, c)), gl_add(gl_mul(a, b), gl_mul(a, c)));
    }

    // -- Byte serialization --------------------------------------------------

    #[test]
    fn test_le_bytes_roundtrip() {
        for &val in &[0u64, 1, 42, 1000, P - 1] {
            let bytes = GoldilocksFr::to_le_bytes(&val);
            let recovered = GoldilocksFr::from_le_bytes(&bytes).unwrap();
            assert_eq!(val, recovered);
        }
    }

    #[test]
    fn test_le_bytes_upper_bytes_zero() {
        let bytes = GoldilocksFr::to_le_bytes(&42);
        assert!(bytes[8..32].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_from_le_bytes_rejects() {
        // Value = p → reject
        let mut p_bytes = [0u8; 32];
        p_bytes[0..8].copy_from_slice(&P.to_le_bytes());
        assert!(GoldilocksFr::from_le_bytes(&p_bytes).is_none());

        // Nonzero upper bytes → reject
        let mut bad = [0u8; 32];
        bad[0] = 1;
        bad[8] = 1; // nonzero in upper region
        assert!(GoldilocksFr::from_le_bytes(&bad).is_none());

        // All 0xFF → reject
        assert!(GoldilocksFr::from_le_bytes(&[0xFF; 32]).is_none());
    }

    // -- String I/O ----------------------------------------------------------

    #[test]
    fn test_decimal_roundtrip() {
        for &val in &[0u64, 1, 42, 123456789, P - 1] {
            let s = GoldilocksFr::to_decimal_string(&val);
            let parsed = GoldilocksFr::from_decimal_str(&s).unwrap();
            assert_eq!(val, parsed, "decimal roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_from_decimal_str_reduces() {
        // p → 0
        let p_str = "18446744069414584321"; // P in decimal
        assert_eq!(GoldilocksFr::from_decimal_str(p_str).unwrap(), 0);
        // p + 1 → 1
        let pp1 = "18446744069414584322";
        assert_eq!(GoldilocksFr::from_decimal_str(pp1).unwrap(), 1);
        // Very large number
        let big = "999999999999999999999999999999999999999";
        let val = GoldilocksFr::from_decimal_str(big).unwrap();
        assert!(val < P);
    }

    #[test]
    fn test_from_decimal_str_invalid() {
        assert!(GoldilocksFr::from_decimal_str("").is_none());
        assert!(GoldilocksFr::from_decimal_str("abc").is_none());
        assert!(GoldilocksFr::from_decimal_str("-1").is_none());
    }

    #[test]
    fn test_hex() {
        assert_eq!(GoldilocksFr::from_hex_str("0x2a").unwrap(), 42);
        assert_eq!(GoldilocksFr::from_hex_str("ff").unwrap(), 255);
        assert!(GoldilocksFr::from_hex_str("").is_none());
    }

    #[test]
    fn test_binary() {
        assert_eq!(GoldilocksFr::from_binary_str("101010").unwrap(), 42);
        assert_eq!(GoldilocksFr::from_binary_str("0").unwrap(), 0);
        assert_eq!(GoldilocksFr::from_binary_str("1").unwrap(), 1);
        assert!(GoldilocksFr::from_binary_str("").is_none());
        assert!(GoldilocksFr::from_binary_str("102").is_none());
    }

    // -- Metadata ------------------------------------------------------------

    #[test]
    fn test_prime_id() {
        assert_eq!(GoldilocksFr::PRIME_ID, PrimeId::Goldilocks);
        assert_eq!(GoldilocksFr::MODULUS_BIT_SIZE, 64);
        assert_eq!(GoldilocksFr::BYTE_SIZE, 8);
    }

    #[test]
    fn test_modulus_le_bytes() {
        let bytes = GoldilocksFr::modulus_le_bytes();
        let limb0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(limb0, P);
        assert!(bytes[8..32].iter().all(|&b| b == 0));
    }

    // -- FieldElement<GoldilocksFr> wrapper ----------------------------------

    #[test]
    fn test_field_element_wrapper() {
        let a = GlFE::from_u64(7);
        let b = GlFE::from_u64(5);
        assert_eq!(a.add(&b).to_canonical(), [12, 0, 0, 0]);
        assert_eq!(a.mul(&b).to_canonical(), [35, 0, 0, 0]);
        assert_eq!(a.sub(&b).to_canonical(), [2, 0, 0, 0]);
        assert!(!a.is_zero());
        assert!(GlFE::zero().is_zero());

        let inv = a.inv().unwrap();
        assert_eq!(a.mul(&inv), GlFE::one());
    }

    #[test]
    fn test_field_element_display() {
        let fe = GlFE::from_u64(42);
        assert_eq!(format!("{}", fe), "42");
        assert_eq!(format!("{:?}", fe), "Field(42)");
    }

    // -- Cross-field distinctness --------------------------------------------

    #[test]
    fn test_different_repr_type() {
        // Goldilocks one = 1 (plain u64)
        assert_eq!(GoldilocksFr::one(), 1u64);
        // BN254 one = R (Montgomery form, not 1)
        let bn_one = crate::Bn254Fr::one();
        assert_ne!(
            bn_one,
            [1, 0, 0, 0],
            "BN254 one in Montgomery form ≠ [1,0,0,0]"
        );
    }

    // -- Edge cases ----------------------------------------------------------

    #[test]
    fn test_p_minus_1_squared() {
        let pm1 = P - 1;
        assert_eq!(gl_mul(pm1, pm1), 1, "(-1)^2 should be 1");
    }

    #[test]
    fn test_p_minus_1_plus_p_minus_1() {
        let pm1 = P - 1;
        assert_eq!(gl_add(pm1, pm1), P - 2, "(p-1)+(p-1) should be p-2");
    }

    #[test]
    fn test_large_mul() {
        let a = GoldilocksFr::from_u64(123456789);
        let b = GoldilocksFr::from_u64(987654321);
        let result = gl_mul(a, b);
        // 123456789 * 987654321 = 121932631112635269
        // This fits in u64 and is < p, so no reduction needed
        assert_eq!(result, 121932631112635269u64);
    }

    #[test]
    fn test_fermat_little_theorem() {
        // a^{p-1} ≡ 1 (mod p) for all a ≠ 0
        for &a in &[2u64, 7, 42, P - 1] {
            let result = GoldilocksFr::pow(&a, &[P - 1, 0, 0, 0]);
            assert_eq!(result, 1, "Fermat failed for a={a}");
        }
    }
}
