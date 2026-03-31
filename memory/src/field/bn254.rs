//! BN254 scalar field (Fr) backend — Montgomery form, `[u64; 4]`.
//!
//! Wraps the existing arithmetic in `arithmetic.rs` behind the `FieldBackend` trait.
//! No new math — just delegation to the battle-tested Montgomery implementation.

use super::arithmetic::*;
use super::backend::FieldBackend;
use super::prime_id::PrimeId;
use crate::limb_ops::sbb;
use serde::Deserialize;

/// BN254 scalar field backend (zero-sized marker type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bn254Fr;

impl FieldBackend for Bn254Fr {
    type Repr = [u64; 4];

    const PRIME_ID: PrimeId = PrimeId::Bn254;
    const MODULUS_BIT_SIZE: u32 = 254;
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
        montgomery4_add(a, b)
    }

    #[inline]
    fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        montgomery4_sub(a, b)
    }

    #[inline]
    fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        montgomery_mul(a, b)
    }

    #[inline]
    fn neg(a: &[u64; 4]) -> [u64; 4] {
        montgomery4_neg(a)
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
                "invalid FieldElement: limbs >= BN254 modulus",
            ));
        }
        Ok(limbs)
    }
}

/// Check if limbs represent a value strictly less than the BN254 modulus.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_and_one() {
        assert!(Bn254Fr::is_zero(&Bn254Fr::zero()));
        assert!(!Bn254Fr::is_zero(&Bn254Fr::one()));
        assert_eq!(Bn254Fr::to_canonical_limbs(&Bn254Fr::one()), [1, 0, 0, 0]);
        assert_eq!(Bn254Fr::to_canonical_limbs(&Bn254Fr::zero()), [0; 4]);
    }

    #[test]
    fn test_from_u64_roundtrip() {
        for &val in &[0u64, 1, 2, 42, 1000, u64::MAX] {
            let repr = Bn254Fr::from_u64(val);
            let canonical = Bn254Fr::to_canonical_limbs(&repr);
            assert_eq!(canonical[0], val);
            assert_eq!(canonical[1], 0);
        }
    }

    #[test]
    fn test_add() {
        let a = Bn254Fr::from_u64(7);
        let b = Bn254Fr::from_u64(5);
        let c = Bn254Fr::add(&a, &b);
        assert_eq!(Bn254Fr::to_canonical_limbs(&c), [12, 0, 0, 0]);
    }

    #[test]
    fn test_mul() {
        let a = Bn254Fr::from_u64(6);
        let b = Bn254Fr::from_u64(7);
        let c = Bn254Fr::mul(&a, &b);
        assert_eq!(Bn254Fr::to_canonical_limbs(&c), [42, 0, 0, 0]);
    }

    #[test]
    fn test_inv() {
        let a = Bn254Fr::from_u64(7);
        let inv = Bn254Fr::inv(&a).unwrap();
        let product = Bn254Fr::mul(&a, &inv);
        assert_eq!(product, Bn254Fr::one());
        assert!(Bn254Fr::inv(&Bn254Fr::zero()).is_none());
    }

    #[test]
    fn test_neg() {
        let a = Bn254Fr::from_u64(5);
        let neg_a = Bn254Fr::neg(&a);
        let sum = Bn254Fr::add(&a, &neg_a);
        assert!(Bn254Fr::is_zero(&sum));
        assert_eq!(Bn254Fr::neg(&Bn254Fr::zero()), Bn254Fr::zero());
    }

    #[test]
    fn test_le_bytes_roundtrip() {
        for &val in &[0u64, 1, 42, 1000, u64::MAX] {
            let repr = Bn254Fr::from_u64(val);
            let bytes = Bn254Fr::to_le_bytes(&repr);
            let recovered = Bn254Fr::from_le_bytes(&bytes).unwrap();
            assert_eq!(repr, recovered);
        }
    }

    #[test]
    fn test_decimal_roundtrip() {
        let repr = Bn254Fr::from_u64(123456789);
        assert_eq!(Bn254Fr::to_decimal_string(&repr), "123456789");
        let parsed = Bn254Fr::from_decimal_str("123456789").unwrap();
        assert_eq!(repr, parsed);
    }

    #[test]
    fn test_hex() {
        let repr = Bn254Fr::from_hex_str("0x2a").unwrap();
        assert_eq!(repr, Bn254Fr::from_u64(42));
    }

    #[test]
    fn test_binary() {
        let repr = Bn254Fr::from_binary_str("101010").unwrap();
        assert_eq!(repr, Bn254Fr::from_u64(42));
    }

    #[test]
    fn test_prime_id() {
        assert_eq!(Bn254Fr::PRIME_ID, PrimeId::Bn254);
        assert_eq!(Bn254Fr::MODULUS_BIT_SIZE, 254);
        assert_eq!(Bn254Fr::BYTE_SIZE, 32);
    }

    #[test]
    fn test_modulus_le_bytes() {
        let bytes = Bn254Fr::modulus_le_bytes();
        let limb0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(limb0, MODULUS[0]);
    }

    /// Cross-validate: Bn254Fr backend produces identical results to FieldElement.
    /// This proves the delegation layer introduces no divergence.
    #[test]
    fn test_backend_matches_field_element() {
        use crate::FieldElement;

        let vals = [0u64, 1, 2, 7, 42, 12345, u64::MAX];
        for &a_val in &vals {
            for &b_val in &vals {
                let fe_a: FieldElement = FieldElement::from_u64(a_val);
                let fe_b = FieldElement::from_u64(b_val);
                let be_a = Bn254Fr::from_u64(a_val);
                let be_b = Bn254Fr::from_u64(b_val);

                // Repr should match
                assert_eq!(fe_a.into_repr(), be_a, "repr mismatch for {a_val}");
                assert_eq!(fe_b.into_repr(), be_b, "repr mismatch for {b_val}");

                // Arithmetic
                assert_eq!(
                    fe_a.add(&fe_b).into_repr(),
                    Bn254Fr::add(&be_a, &be_b),
                    "add({a_val},{b_val})"
                );
                assert_eq!(
                    fe_a.sub(&fe_b).into_repr(),
                    Bn254Fr::sub(&be_a, &be_b),
                    "sub({a_val},{b_val})"
                );
                assert_eq!(
                    fe_a.mul(&fe_b).into_repr(),
                    Bn254Fr::mul(&be_a, &be_b),
                    "mul({a_val},{b_val})"
                );
                assert_eq!(fe_a.neg().into_repr(), Bn254Fr::neg(&be_a), "neg({a_val})");

                // Canonical roundtrip
                assert_eq!(fe_a.to_canonical(), Bn254Fr::to_canonical_limbs(&be_a));
                assert_eq!(fe_a.to_le_bytes(), Bn254Fr::to_le_bytes(&be_a));
                assert_eq!(fe_a.to_decimal_string(), Bn254Fr::to_decimal_string(&be_a));
            }
        }

        // Inverse (skip zero)
        for &v in &[1u64, 7, 42, u64::MAX] {
            let fe: FieldElement = FieldElement::from_u64(v);
            let be = Bn254Fr::from_u64(v);
            assert_eq!(
                fe.inv().unwrap().into_repr(),
                Bn254Fr::inv(&be).unwrap(),
                "inv({v})"
            );
        }

        // Constants
        assert_eq!(FieldElement::ZERO.into_repr(), Bn254Fr::zero());
        assert_eq!(FieldElement::ONE.into_repr(), Bn254Fr::one());
    }
}
