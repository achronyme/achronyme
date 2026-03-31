//! BLS12-381 scalar field (Fr) backend — Montgomery form, `[u64; 4]`.
//!
//! Same CIOS Montgomery algorithm as BN254, different constants.
//! Reuses `mul_wide`, `gte`, and `montgomery4_ct_select` from `arithmetic.rs`.

use super::arithmetic::{gte, montgomery4_ct_select, mul_wide};
use super::backend::FieldBackend;
use super::prime_id::PrimeId;
use crate::limb_ops::{adc, mac, sbb};
use serde::Deserialize;

// ============================================================================
// BLS12-381 Fr Constants
// ============================================================================

/// The prime modulus p (BLS12-381 Fr)
/// p = 52435875175126190479447740508185965837690552500527637822603658699938581184513
const MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

/// R = 2^256 mod p (Montgomery constant)
const R: [u64; 4] = [
    0x00000001fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
];

/// R^2 = (2^256)^2 mod p (for converting to Montgomery form)
const R2: [u64; 4] = [
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
];

/// Montgomery inverse: -p^{-1} mod 2^64
const INV: u64 = 0xfffffffeffffffff;

/// p - 2 (for Fermat's little theorem inversion)
const P_MINUS_2: [u64; 4] = [
    0xfffffffeffffffff,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

// ============================================================================
// Montgomery operations (BLS12-381 specific)
// ============================================================================

/// Conditionally subtract BLS12-381 modulus if value >= MODULUS (constant-time).
#[inline]
fn subtract_modulus_if_needed(limbs: &mut [u64; 4]) {
    let (r0, borrow) = sbb(limbs[0], MODULUS[0], 0);
    let (r1, borrow) = sbb(limbs[1], MODULUS[1], borrow);
    let (r2, borrow) = sbb(limbs[2], MODULUS[2], borrow);
    let (r3, borrow) = sbb(limbs[3], MODULUS[3], borrow);
    let mask = 0u64.wrapping_sub(borrow);
    limbs[0] = (limbs[0] & mask) | (r0 & !mask);
    limbs[1] = (limbs[1] & mask) | (r1 & !mask);
    limbs[2] = (limbs[2] & mask) | (r2 & !mask);
    limbs[3] = (limbs[3] & mask) | (r3 & !mask);
}

/// Montgomery reduction for BLS12-381: T · R⁻¹ mod p (CIOS).
fn montgomery_reduce(t: &[u64; 8]) -> [u64; 4] {
    let (r0, mut r1, mut r2, mut r3) = (t[0], t[1], t[2], t[3]);
    let (mut r4, mut r5, mut r6, mut r7) = (t[4], t[5], t[6], t[7]);

    // Iteration 0
    let k = r0.wrapping_mul(INV);
    let (_, mut carry) = mac(k, MODULUS[0], r0, 0);
    (r1, carry) = mac(k, MODULUS[1], r1, carry);
    (r2, carry) = mac(k, MODULUS[2], r2, carry);
    (r3, carry) = mac(k, MODULUS[3], r3, carry);
    let mut carry2;
    (r4, carry2) = adc(r4, carry, 0);

    // Iteration 1
    let k = r1.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r1, 0);
    (r2, carry) = mac(k, MODULUS[1], r2, carry);
    (r3, carry) = mac(k, MODULUS[2], r3, carry);
    (r4, carry) = mac(k, MODULUS[3], r4, carry);
    (r5, carry2) = adc(r5, carry, carry2);

    // Iteration 2
    let k = r2.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r2, 0);
    (r3, carry) = mac(k, MODULUS[1], r3, carry);
    (r4, carry) = mac(k, MODULUS[2], r4, carry);
    (r5, carry) = mac(k, MODULUS[3], r5, carry);
    (r6, carry2) = adc(r6, carry, carry2);

    // Iteration 3
    let k = r3.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r3, 0);
    (r4, carry) = mac(k, MODULUS[1], r4, carry);
    (r5, carry) = mac(k, MODULUS[2], r5, carry);
    (r6, carry) = mac(k, MODULUS[3], r6, carry);
    (r7, _) = adc(r7, carry, carry2);

    let mut result = [r4, r5, r6, r7];
    subtract_modulus_if_needed(&mut result);
    result
}

/// Montgomery multiplication for BLS12-381: a * b * R^{-1} mod p.
#[inline]
fn montgomery_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    montgomery_reduce(&mul_wide(a, b))
}

/// Modular addition for BLS12-381: (a + b) mod p.
#[inline]
fn montgomery_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, carry) = adc(a[0], b[0], 0);
    let (r1, carry) = adc(a[1], b[1], carry);
    let (r2, carry) = adc(a[2], b[2], carry);
    let (r3, _) = adc(a[3], b[3], carry);
    let mut result = [r0, r1, r2, r3];
    subtract_modulus_if_needed(&mut result);
    result
}

/// Modular subtraction for BLS12-381: (a - b) mod p (constant-time).
#[inline]
fn montgomery_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow) = sbb(a[0], b[0], 0);
    let (r1, borrow) = sbb(a[1], b[1], borrow);
    let (r2, borrow) = sbb(a[2], b[2], borrow);
    let (r3, borrow) = sbb(a[3], b[3], borrow);
    let mask = 0u64.wrapping_sub(borrow);
    let (r0, carry) = adc(r0, MODULUS[0] & mask, 0);
    let (r1, carry) = adc(r1, MODULUS[1] & mask, carry);
    let (r2, carry) = adc(r2, MODULUS[2] & mask, carry);
    let (r3, _) = adc(r3, MODULUS[3] & mask, carry);
    [r0, r1, r2, r3]
}

/// Modular negation for BLS12-381: (-a) mod p (constant-time).
#[inline]
fn montgomery_neg(a: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow) = sbb(MODULUS[0], a[0], 0);
    let (r1, borrow) = sbb(MODULUS[1], a[1], borrow);
    let (r2, borrow) = sbb(MODULUS[2], a[2], borrow);
    let (r3, _) = sbb(MODULUS[3], a[3], borrow);
    let is_nonzero = a[0] | a[1] | a[2] | a[3];
    let mask = (is_nonzero | is_nonzero.wrapping_neg()) >> 63;
    let mask = 0u64.wrapping_sub(mask);
    [r0 & mask, r1 & mask, r2 & mask, r3 & mask]
}

// ============================================================================
// FieldBackend implementation
// ============================================================================

/// BLS12-381 scalar field backend (zero-sized marker type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bls12_381Fr;

impl FieldBackend for Bls12_381Fr {
    type Repr = [u64; 4];

    const PRIME_ID: PrimeId = PrimeId::Bls12_381;
    const MODULUS_BIT_SIZE: u32 = 255;
    const BYTE_SIZE: usize = 32;

    // ========================================================================
    // Constants
    // ========================================================================

    #[inline]
    fn zero() -> [u64; 4] {
        [0; 4]
    }

    #[inline]
    fn one() -> [u64; 4] {
        R // 1 in Montgomery form = R mod p
    }

    // ========================================================================
    // Construction
    // ========================================================================

    fn from_u64(val: u64) -> [u64; 4] {
        let canonical = [val, 0, 0, 0];
        montgomery_mul(&canonical, &R2)
    }

    fn from_i64(val: i64) -> [u64; 4] {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            Self::neg(&Self::from_u64(val.unsigned_abs()))
        }
    }

    fn from_canonical_limbs(limbs: &[u64]) -> [u64; 4] {
        let mut canonical = [0u64; 4];
        let n = limbs.len().min(4);
        canonical[..n].copy_from_slice(&limbs[..n]);
        montgomery_mul(&canonical, &R2)
    }

    fn to_canonical_limbs(a: &[u64; 4]) -> [u64; 4] {
        // Multiply by 1 to remove Montgomery factor: a * R^{-1} mod p
        montgomery_reduce(&[a[0], a[1], a[2], a[3], 0, 0, 0, 0])
    }

    // ========================================================================
    // Arithmetic
    // ========================================================================

    #[inline]
    fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        montgomery_add(a, b)
    }

    #[inline]
    fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        montgomery_sub(a, b)
    }

    #[inline]
    fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        montgomery_mul(a, b)
    }

    #[inline]
    fn neg(a: &[u64; 4]) -> [u64; 4] {
        montgomery_neg(a)
    }

    fn inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        if Self::is_zero(a) {
            return None;
        }
        Some(Self::pow(a, &P_MINUS_2))
    }

    #[inline]
    fn is_zero(a: &[u64; 4]) -> bool {
        *a == [0; 4]
    }

    fn pow(base: &[u64; 4], exp: &[u64; 4]) -> [u64; 4] {
        let mut result = Self::one();
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                result = Self::mul(&result, &result);
                let multiplied = Self::mul(&result, base);
                let flag = (exp[i] >> bit) & 1;
                result = Self::ct_select(&result, &multiplied, flag);
            }
        }
        result
    }

    #[inline]
    fn ct_select(a: &[u64; 4], b: &[u64; 4], flag: u64) -> [u64; 4] {
        montgomery4_ct_select(a, b, flag)
    }

    // ========================================================================
    // Byte serialization
    // ========================================================================

    fn to_le_bytes(a: &[u64; 4]) -> [u8; 32] {
        let canonical = Self::to_canonical_limbs(a);
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&canonical[i].to_le_bytes());
        }
        bytes
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<[u64; 4]> {
        if bytes.len() < 32 {
            return None;
        }
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().ok()?);
        }
        if gte(&limbs, &MODULUS) {
            return None;
        }
        Some(Self::from_canonical_limbs(&limbs))
    }

    // ========================================================================
    // String I/O
    // ========================================================================

    fn to_decimal_string(a: &[u64; 4]) -> String {
        let canonical = Self::to_canonical_limbs(a);
        if canonical == [0; 4] {
            return "0".to_string();
        }
        let mut limbs = canonical;
        let mut digits = Vec::new();
        loop {
            if limbs[0] == 0 && limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                break;
            }
            let mut remainder = 0u128;
            for i in (0..4).rev() {
                let combined = (remainder << 64) | limbs[i] as u128;
                limbs[i] = (combined / 10) as u64;
                remainder = combined % 10;
            }
            digits.push((remainder as u8) + b'0');
        }
        if digits.is_empty() {
            "0".to_string()
        } else {
            digits.reverse();
            String::from_utf8(digits).unwrap()
        }
    }

    fn from_decimal_str(s: &str) -> Option<[u64; 4]> {
        if s.is_empty() {
            return None;
        }
        let mut result = [0u64; 5];
        for ch in s.chars() {
            let digit = ch.to_digit(10)? as u64;
            let mut carry = 0u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 * 10 + carry;
                *limb = wide as u64;
                carry = wide >> 64;
            }
            let mut add_carry = digit as u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 + add_carry;
                *limb = wide as u64;
                add_carry = wide >> 64;
            }
            loop {
                if result[4] == 0 && !gte(&[result[0], result[1], result[2], result[3]], &MODULUS) {
                    break;
                }
                let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
                let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
                let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
                let (r3, borrow) = sbb(result[3], MODULUS[3], borrow);
                let (r4, _) = sbb(result[4], 0, borrow);
                result = [r0, r1, r2, r3, r4];
            }
        }
        Some(Self::from_canonical_limbs(&[
            result[0], result[1], result[2], result[3],
        ]))
    }

    fn from_hex_str(s: &str) -> Option<[u64; 4]> {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        let padded = format!("{:0>64}", hex);
        let mut result = [0u64; 4];
        result[3] = u64::from_str_radix(&padded[0..16], 16).ok()?;
        result[2] = u64::from_str_radix(&padded[16..32], 16).ok()?;
        result[1] = u64::from_str_radix(&padded[32..48], 16).ok()?;
        result[0] = u64::from_str_radix(&padded[48..64], 16).ok()?;
        while gte(&result, &MODULUS) {
            let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
            let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
            let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
            let (r3, _) = sbb(result[3], MODULUS[3], borrow);
            result = [r0, r1, r2, r3];
        }
        Some(Self::from_canonical_limbs(&result))
    }

    fn from_binary_str(s: &str) -> Option<[u64; 4]> {
        if s.is_empty() || s.len() > 256 {
            return None;
        }
        let mut result = [0u64; 4];
        for ch in s.chars() {
            let digit = match ch {
                '0' => 0u64,
                '1' => 1u64,
                _ => return None,
            };
            let mut carry = 0u64;
            for limb in result.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            let mut add_carry = digit as u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 + add_carry;
                *limb = wide as u64;
                add_carry = wide >> 64;
            }
        }
        while gte(&result, &MODULUS) {
            let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
            let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
            let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
            let (r3, _) = sbb(result[3], MODULUS[3], borrow);
            result = [r0, r1, r2, r3];
        }
        Some(Self::from_canonical_limbs(&result))
    }

    // ========================================================================
    // Modulus
    // ========================================================================

    fn modulus_le_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&MODULUS[i].to_le_bytes());
        }
        bytes
    }

    // ========================================================================
    // Serde
    // ========================================================================

    fn serde_serialize<S: serde::Serializer>(
        a: &[u64; 4],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(a, serializer)
    }

    fn serde_deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u64; 4], D::Error> {
        let limbs = <[u64; 4]>::deserialize(deserializer)?;
        if !limbs_less_than_modulus(&limbs) {
            return Err(serde::de::Error::custom(
                "invalid FieldElement: limbs >= BLS12-381 modulus",
            ));
        }
        Ok(limbs)
    }
}

/// Check if limbs represent a value strictly less than the BLS12-381 modulus.
fn limbs_less_than_modulus(limbs: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if limbs[i] < MODULUS[i] {
            return true;
        }
        if limbs[i] > MODULUS[i] {
            return false;
        }
    }
    false // equal → not less than
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldElement;

    type BlsFE = FieldElement<Bls12_381Fr>;

    // -- Constant verification with BigUint ----------------------------------

    fn limbs_to_bigint(limbs: &[u64; 4]) -> num_bigint::BigUint {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        num_bigint::BigUint::from_bytes_le(&bytes)
    }

    #[test]
    fn test_verify_constants_with_bigint() {
        use num_traits::One;
        let p = limbs_to_bigint(&MODULUS);

        // R = 2^256 mod p
        let two_256 = num_bigint::BigUint::one() << 256;
        assert_eq!(limbs_to_bigint(&R), &two_256 % &p, "R constant is wrong");

        // R^2 = R * R mod p
        let r = &two_256 % &p;
        assert_eq!(limbs_to_bigint(&R2), (&r * &r) % &p, "R2 constant is wrong");

        // INV: MODULUS[0] * INV ≡ -1 (mod 2^64)
        assert_eq!(
            MODULUS[0].wrapping_mul(INV),
            u64::MAX,
            "INV constant is wrong"
        );

        // P_MINUS_2 = p - 2
        let pm2 = &p - num_bigint::BigUint::from(2u64);
        assert_eq!(
            limbs_to_bigint(&P_MINUS_2),
            pm2,
            "P_MINUS_2 constant is wrong"
        );

        // Montgomery reduce(R) should give 1
        assert_eq!(
            montgomery_reduce(&[R[0], R[1], R[2], R[3], 0, 0, 0, 0]),
            [1, 0, 0, 0],
            "reduce(R) must be 1"
        );

        // to_Montgomery(1) = R
        assert_eq!(montgomery_mul(&[1, 0, 0, 0], &R2), R, "1 * R2 must be R");
    }

    // -- Zero and one --------------------------------------------------------

    #[test]
    fn test_zero_and_one() {
        assert!(Bls12_381Fr::is_zero(&Bls12_381Fr::zero()));
        assert!(!Bls12_381Fr::is_zero(&Bls12_381Fr::one()));
        assert_eq!(
            Bls12_381Fr::to_canonical_limbs(&Bls12_381Fr::one()),
            [1, 0, 0, 0]
        );
        assert_eq!(
            Bls12_381Fr::to_canonical_limbs(&Bls12_381Fr::zero()),
            [0; 4]
        );
    }

    // -- Construction --------------------------------------------------------

    #[test]
    fn test_from_u64_roundtrip() {
        for &val in &[0u64, 1, 2, 42, 1000, u64::MAX] {
            let repr = Bls12_381Fr::from_u64(val);
            let canonical = Bls12_381Fr::to_canonical_limbs(&repr);
            assert_eq!(canonical[0], val, "from_u64({val}) roundtrip failed");
            assert_eq!(canonical[1], 0);
        }
    }

    #[test]
    fn test_from_i64_negative() {
        let neg_one = Bls12_381Fr::from_i64(-1);
        let sum = Bls12_381Fr::add(&Bls12_381Fr::one(), &neg_one);
        assert!(Bls12_381Fr::is_zero(&sum), "-1 + 1 should be 0");
    }

    // -- Arithmetic ----------------------------------------------------------

    #[test]
    fn test_add() {
        let a = Bls12_381Fr::from_u64(7);
        let b = Bls12_381Fr::from_u64(5);
        let c = Bls12_381Fr::add(&a, &b);
        assert_eq!(Bls12_381Fr::to_canonical_limbs(&c), [12, 0, 0, 0]);
    }

    #[test]
    fn test_sub() {
        let a = Bls12_381Fr::from_u64(10);
        let b = Bls12_381Fr::from_u64(3);
        let c = Bls12_381Fr::sub(&a, &b);
        assert_eq!(Bls12_381Fr::to_canonical_limbs(&c), [7, 0, 0, 0]);
    }

    #[test]
    fn test_sub_underflow() {
        // 3 - 10 should wrap around mod p
        let a = Bls12_381Fr::from_u64(3);
        let b = Bls12_381Fr::from_u64(10);
        let c = Bls12_381Fr::sub(&a, &b);
        // c + 7 should equal 0 (mod p)
        let seven = Bls12_381Fr::from_u64(7);
        assert!(Bls12_381Fr::is_zero(&Bls12_381Fr::add(&c, &seven)));
    }

    #[test]
    fn test_mul() {
        let a = Bls12_381Fr::from_u64(6);
        let b = Bls12_381Fr::from_u64(7);
        let c = Bls12_381Fr::mul(&a, &b);
        assert_eq!(Bls12_381Fr::to_canonical_limbs(&c), [42, 0, 0, 0]);
    }

    #[test]
    fn test_neg() {
        let a = Bls12_381Fr::from_u64(5);
        let neg_a = Bls12_381Fr::neg(&a);
        let sum = Bls12_381Fr::add(&a, &neg_a);
        assert!(Bls12_381Fr::is_zero(&sum));
        assert_eq!(Bls12_381Fr::neg(&Bls12_381Fr::zero()), Bls12_381Fr::zero());
    }

    #[test]
    fn test_inv() {
        let a = Bls12_381Fr::from_u64(7);
        let inv = Bls12_381Fr::inv(&a).unwrap();
        let product = Bls12_381Fr::mul(&a, &inv);
        assert_eq!(product, Bls12_381Fr::one(), "7 * inv(7) must be 1");
        assert!(Bls12_381Fr::inv(&Bls12_381Fr::zero()).is_none());
    }

    #[test]
    fn test_pow() {
        let base = Bls12_381Fr::from_u64(2);
        let result = Bls12_381Fr::pow(&base, &[10, 0, 0, 0]);
        assert_eq!(Bls12_381Fr::to_canonical_limbs(&result), [1024, 0, 0, 0]);
    }

    #[test]
    fn test_multiplicative_identity() {
        let a = Bls12_381Fr::from_u64(12345);
        assert_eq!(Bls12_381Fr::mul(&a, &Bls12_381Fr::one()), a);
        assert_eq!(Bls12_381Fr::mul(&Bls12_381Fr::one(), &a), a);
    }

    #[test]
    fn test_additive_identity() {
        let a = Bls12_381Fr::from_u64(12345);
        assert_eq!(Bls12_381Fr::add(&a, &Bls12_381Fr::zero()), a);
    }

    // -- Byte serialization --------------------------------------------------

    #[test]
    fn test_le_bytes_roundtrip() {
        for &val in &[0u64, 1, 42, 1000, u64::MAX] {
            let repr = Bls12_381Fr::from_u64(val);
            let bytes = Bls12_381Fr::to_le_bytes(&repr);
            let recovered = Bls12_381Fr::from_le_bytes(&bytes).unwrap();
            assert_eq!(repr, recovered);
        }
    }

    #[test]
    fn test_from_le_bytes_rejects_gte_modulus() {
        let mut p_bytes = [0u8; 32];
        for i in 0..4 {
            p_bytes[i * 8..(i + 1) * 8].copy_from_slice(&MODULUS[i].to_le_bytes());
        }
        assert!(
            Bls12_381Fr::from_le_bytes(&p_bytes).is_none(),
            "p should be rejected"
        );

        let max_bytes = [0xFF; 32];
        assert!(
            Bls12_381Fr::from_le_bytes(&max_bytes).is_none(),
            "2^256-1 should be rejected"
        );
    }

    // -- String I/O ----------------------------------------------------------

    #[test]
    fn test_decimal_roundtrip() {
        let repr = Bls12_381Fr::from_u64(123456789);
        assert_eq!(Bls12_381Fr::to_decimal_string(&repr), "123456789");
        let parsed = Bls12_381Fr::from_decimal_str("123456789").unwrap();
        assert_eq!(repr, parsed);
    }

    #[test]
    fn test_hex() {
        let repr = Bls12_381Fr::from_hex_str("0x2a").unwrap();
        assert_eq!(repr, Bls12_381Fr::from_u64(42));
    }

    #[test]
    fn test_binary() {
        let repr = Bls12_381Fr::from_binary_str("101010").unwrap();
        assert_eq!(repr, Bls12_381Fr::from_u64(42));
    }

    #[test]
    fn test_from_decimal_str_exactly_p() {
        let p_str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
        let parsed = Bls12_381Fr::from_decimal_str(p_str).unwrap();
        assert!(Bls12_381Fr::is_zero(&parsed), "p mod p should be 0");
    }

    #[test]
    fn test_from_decimal_str_p_plus_1() {
        let p_plus_1 =
            "52435875175126190479447740508185965837690552500527637822603658699938581184514";
        let parsed = Bls12_381Fr::from_decimal_str(p_plus_1).unwrap();
        assert_eq!(parsed, Bls12_381Fr::one(), "p + 1 mod p should be 1");
    }

    // -- Metadata ------------------------------------------------------------

    #[test]
    fn test_prime_id() {
        assert_eq!(Bls12_381Fr::PRIME_ID, PrimeId::Bls12_381);
        assert_eq!(Bls12_381Fr::MODULUS_BIT_SIZE, 255);
        assert_eq!(Bls12_381Fr::BYTE_SIZE, 32);
    }

    #[test]
    fn test_modulus_le_bytes() {
        let bytes = Bls12_381Fr::modulus_le_bytes();
        let limb0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(limb0, MODULUS[0]);
    }

    // -- FieldElement<Bls12_381Fr> wrapper ------------------------------------

    #[test]
    fn test_field_element_wrapper() {
        let a = BlsFE::from_u64(7);
        let b = BlsFE::from_u64(5);
        assert_eq!(a.add(&b).to_canonical(), [12, 0, 0, 0]);
        assert_eq!(a.mul(&b).to_canonical(), [35, 0, 0, 0]);
        assert_eq!(a.sub(&b).to_canonical(), [2, 0, 0, 0]);
        assert!(!a.is_zero());
        assert!(BlsFE::zero().is_zero());

        let inv = a.inv().unwrap();
        assert_eq!(a.mul(&inv), BlsFE::one());
    }

    #[test]
    fn test_field_element_display() {
        let fe = BlsFE::from_u64(42);
        assert_eq!(format!("{}", fe), "42");
        assert_eq!(format!("{:?}", fe), "Field(42)");
    }

    // -- Cross-field: BN254 and BLS12-381 must NOT be interchangeable --------

    #[test]
    fn test_different_moduli() {
        // Same value, different fields — internal representations differ
        let bn_one = crate::FieldElement::ONE.into_repr();
        let bls_one = BlsFE::one().into_repr();
        // Both are "1" but Montgomery R differs between fields
        assert_ne!(
            bn_one, bls_one,
            "R constants must differ between BN254 and BLS12-381"
        );
    }

    // -- Near-overflow arithmetic (field-specific edge cases) ----------------

    #[test]
    fn test_p_minus_1_squared() {
        // (p-1)^2 = (-1)^2 = 1
        let p_minus_1_str =
            "52435875175126190479447740508185965837690552500527637822603658699938581184512";
        let p_minus_1 = Bls12_381Fr::from_decimal_str(p_minus_1_str).unwrap();
        let result = Bls12_381Fr::mul(&p_minus_1, &p_minus_1);
        assert_eq!(result, Bls12_381Fr::one(), "(-1)^2 should be 1");
    }

    #[test]
    fn test_p_minus_1_plus_p_minus_1() {
        // (p-1) + (p-1) = 2p - 2 = p - 2 (mod p)
        let p_minus_1_str =
            "52435875175126190479447740508185965837690552500527637822603658699938581184512";
        let p_minus_1 = Bls12_381Fr::from_decimal_str(p_minus_1_str).unwrap();
        let result = Bls12_381Fr::add(&p_minus_1, &p_minus_1);
        let p_minus_2_str =
            "52435875175126190479447740508185965837690552500527637822603658699938581184511";
        let expected = Bls12_381Fr::from_decimal_str(p_minus_2_str).unwrap();
        assert_eq!(result, expected, "(p-1)+(p-1) should be p-2");
    }

    #[test]
    fn test_large_mul() {
        let a = Bls12_381Fr::from_u64(123456789);
        let b = Bls12_381Fr::from_u64(987654321);
        let result = Bls12_381Fr::mul(&a, &b);
        let expected = Bls12_381Fr::from_decimal_str("121932631112635269").unwrap();
        assert_eq!(result, expected);
    }
}
