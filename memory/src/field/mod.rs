/// BN254 Scalar Field (Fr) Element — Montgomery Form
///
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// Internal representation: value * R mod p (Montgomery domain)
/// Zero external dependencies.
pub(crate) mod arithmetic;
mod parsing;

pub use arithmetic::MODULUS;

use crate::limb_ops::{adc, sbb};
use arithmetic::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldElement {
    /// Four 64-bit limbs in little-endian order (limbs[0] is least significant)
    pub(crate) limbs: [u64; 4],
}

// ============================================================================
// FieldElement public API
// ============================================================================

impl FieldElement {
    /// The zero element (0 in Montgomery form = 0)
    pub const ZERO: Self = Self { limbs: [0; 4] };

    /// The one element (1 in Montgomery form = R mod p)
    pub const ONE: Self = Self { limbs: R };

    /// Create from a small u64 value.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_u64(42);
    /// assert_eq!(fe.to_canonical(), [42, 0, 0, 0]);
    /// ```
    pub fn from_u64(val: u64) -> Self {
        // Convert to Montgomery form: val * R mod p = val * R2 * R^{-1} mod p
        let canonical = [val, 0, 0, 0];
        Self {
            limbs: montgomery_mul(&canonical, &R2),
        }
    }

    /// Create from a signed i64 value
    pub fn from_i64(val: i64) -> Self {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            // Use unsigned_abs() to handle i64::MIN safely ((-i64::MIN) overflows)
            Self::from_u64(val.unsigned_abs()).neg()
        }
    }

    /// Create from canonical form [u64; 4] (already reduced mod p)
    pub fn from_canonical(limbs: [u64; 4]) -> Self {
        // Convert to Montgomery: limbs * R mod p
        Self {
            limbs: montgomery_mul(&limbs, &R2),
        }
    }

    /// Convert back to canonical form (from Montgomery).
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// assert_eq!(FieldElement::ONE.to_canonical(), [1, 0, 0, 0]);
    /// assert_eq!(FieldElement::ZERO.to_canonical(), [0, 0, 0, 0]);
    /// ```
    pub fn to_canonical(&self) -> [u64; 4] {
        // Multiply by 1 to remove Montgomery factor: self * R^{-1} mod p
        montgomery_reduce(&[
            self.limbs[0],
            self.limbs[1],
            self.limbs[2],
            self.limbs[3],
            0,
            0,
            0,
            0,
        ])
    }

    /// Check if zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }

    /// Modular addition: (self + other) mod p.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let a = FieldElement::from_u64(7);
    /// let b = FieldElement::from_u64(5);
    /// assert_eq!(a.add(&b), FieldElement::from_u64(12));
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        let (r0, carry) = adc(self.limbs[0], other.limbs[0], 0);
        let (r1, carry) = adc(self.limbs[1], other.limbs[1], carry);
        let (r2, carry) = adc(self.limbs[2], other.limbs[2], carry);
        let (r3, _) = adc(self.limbs[3], other.limbs[3], carry);
        let mut result = [r0, r1, r2, r3];
        subtract_modulus_if_needed(&mut result);
        Self { limbs: result }
    }

    /// Modular subtraction: (self - other) mod p (constant-time).
    ///
    /// Always computes both the raw subtraction and the modular correction
    /// (add p back), then selects via branchless mask based on borrow.
    pub fn sub(&self, other: &Self) -> Self {
        let (r0, borrow) = sbb(self.limbs[0], other.limbs[0], 0);
        let (r1, borrow) = sbb(self.limbs[1], other.limbs[1], borrow);
        let (r2, borrow) = sbb(self.limbs[2], other.limbs[2], borrow);
        let (r3, borrow) = sbb(self.limbs[3], other.limbs[3], borrow);

        // mask = 0xFFFF...FFFF if borrow (underflow), 0x0000...0000 otherwise
        let mask = 0u64.wrapping_sub(borrow);
        let (r0, carry) = adc(r0, MODULUS[0] & mask, 0);
        let (r1, carry) = adc(r1, MODULUS[1] & mask, carry);
        let (r2, carry) = adc(r2, MODULUS[2] & mask, carry);
        let (r3, _) = adc(r3, MODULUS[3] & mask, carry);
        Self {
            limbs: [r0, r1, r2, r3],
        }
    }

    /// Modular multiplication: (self * other) mod p.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let a = FieldElement::from_u64(6);
    /// let b = FieldElement::from_u64(7);
    /// assert_eq!(a.mul(&b), FieldElement::from_u64(42));
    /// ```
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        Self {
            limbs: montgomery_mul(&self.limbs, &other.limbs),
        }
    }

    /// Modular negation: (-self) mod p (constant-time).
    ///
    /// Computes p - self, then masks to zero if self was zero.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let a = FieldElement::from_u64(5);
    /// assert!(a.add(&a.neg()).is_zero());
    /// assert_eq!(FieldElement::ZERO.neg(), FieldElement::ZERO);
    /// ```
    pub fn neg(&self) -> Self {
        let (r0, borrow) = sbb(MODULUS[0], self.limbs[0], 0);
        let (r1, borrow) = sbb(MODULUS[1], self.limbs[1], borrow);
        let (r2, borrow) = sbb(MODULUS[2], self.limbs[2], borrow);
        let (r3, _) = sbb(MODULUS[3], self.limbs[3], borrow);
        // If self == 0, p - 0 = p which should be 0. Mask out if all input limbs are 0.
        let is_nonzero = self.limbs[0] | self.limbs[1] | self.limbs[2] | self.limbs[3];
        // mask = 0xFFFF...FFFF if nonzero, 0 if zero
        let mask = (is_nonzero | is_nonzero.wrapping_neg()) >> 63;
        let mask = 0u64.wrapping_sub(mask);
        Self {
            limbs: [r0 & mask, r1 & mask, r2 & mask, r3 & mask],
        }
    }

    /// Constant-time conditional select: returns `a` if flag==0, `b` if flag==1.
    /// `flag` MUST be 0 or 1.
    #[inline]
    fn ct_select(a: &Self, b: &Self, flag: u64) -> Self {
        let mask = 0u64.wrapping_sub(flag); // 0 or 0xFFFF...FFFF
        Self {
            limbs: [
                (a.limbs[0] & !mask) | (b.limbs[0] & mask),
                (a.limbs[1] & !mask) | (b.limbs[1] & mask),
                (a.limbs[2] & !mask) | (b.limbs[2] & mask),
                (a.limbs[3] & !mask) | (b.limbs[3] & mask),
            ],
        }
    }

    /// Modular exponentiation: self^exp mod p (constant-time).
    ///
    /// Always performs both square and multiply, then uses `ct_select`
    /// to pick the result based on the exponent bit. This prevents
    /// timing side-channels that leak exponent bits.
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                result = result.mul(&result); // always square
                let multiplied = result.mul(self); // always multiply
                let flag = (exp[i] >> bit) & 1;
                result = Self::ct_select(&result, &multiplied, flag);
            }
        }
        result
    }

    /// Modular inverse: self⁻¹ mod p via Fermat's little theorem (a^(p−2) mod p).
    ///
    /// This requires ~256 field multiplications (one square + one conditional
    /// multiply per exponent bit). Extended GCD would be ~40% faster but is
    /// **not constant-time** — its runtime leaks information about the input
    /// through branch timing. The exponentiation approach is inherently
    /// constant-time because `pow` uses `ct_select` (branchless) for every bit.
    ///
    /// Returns `None` if `self` is zero.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let a = FieldElement::from_u64(7);
    /// let inv = a.inv().unwrap();
    /// assert_eq!(a.mul(&inv), FieldElement::ONE);
    ///
    /// assert!(FieldElement::ZERO.inv().is_none());
    /// ```
    pub fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(&P_MINUS_2))
    }

    /// Modular division: self / other mod p
    /// Returns None if other is zero
    pub fn div(&self, other: &Self) -> Option<Self> {
        Some(self.mul(&other.inv()?))
    }
}

impl std::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Field({})", self.to_decimal_string())
    }
}

impl std::fmt::Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_decimal_string())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

        // R2 = R^2 mod p
        let r = &two_256 % &p;
        assert_eq!(limbs_to_bigint(&R2), (&r * &r) % &p, "R2 constant is wrong");

        // INV: p[0] * INV ≡ -1 (mod 2^64)
        assert_eq!(MODULUS[0].wrapping_mul(INV), u64::MAX);

        // montgomery_reduce(R || 0) = 1
        assert_eq!(
            montgomery_reduce(&[R[0], R[1], R[2], R[3], 0, 0, 0, 0]),
            [1, 0, 0, 0]
        );

        // montgomery_mul(1, R2) = R
        assert_eq!(montgomery_mul(&[1, 0, 0, 0], &R2), R);
    }

    #[test]
    fn test_zero_and_one() {
        assert!(FieldElement::ZERO.is_zero());
        assert!(!FieldElement::ONE.is_zero());
        assert_eq!(FieldElement::ONE.to_canonical(), [1, 0, 0, 0]);
        assert_eq!(FieldElement::ZERO.to_canonical(), [0, 0, 0, 0]);
    }

    #[test]
    fn test_from_u64_roundtrip() {
        for &val in &[0u64, 1, 2, 42, 1000, u64::MAX] {
            let fe = FieldElement::from_u64(val);
            let canonical = fe.to_canonical();
            // For values < p, limbs[1..] should be 0, limbs[0] == val
            // u64::MAX < p, so this holds
            assert_eq!(canonical[0], val);
            assert_eq!(canonical[1], 0);
            assert_eq!(canonical[2], 0);
            assert_eq!(canonical[3], 0);
        }
    }

    #[test]
    fn test_addition() {
        let a = FieldElement::from_u64(7);
        let b = FieldElement::from_u64(5);
        let c = a.add(&b);
        assert_eq!(c.to_canonical(), [12, 0, 0, 0]);
    }

    #[test]
    fn test_subtraction() {
        let a = FieldElement::from_u64(10);
        let b = FieldElement::from_u64(3);
        let c = a.sub(&b);
        assert_eq!(c.to_canonical(), [7, 0, 0, 0]);
    }

    #[test]
    fn test_subtraction_underflow() {
        // 3 - 10 mod p = p - 7
        let a = FieldElement::from_u64(3);
        let b = FieldElement::from_u64(10);
        let c = a.sub(&b);
        let expected = FieldElement::from_u64(0).sub(&FieldElement::from_u64(7));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_multiplication() {
        let a = FieldElement::from_u64(6);
        let b = FieldElement::from_u64(7);
        let c = a.mul(&b);
        assert_eq!(c.to_canonical(), [42, 0, 0, 0]);
    }

    #[test]
    fn test_negation() {
        let a = FieldElement::from_u64(5);
        let neg_a = a.neg();
        let sum = a.add(&neg_a);
        assert!(sum.is_zero());
    }

    #[test]
    fn test_negation_zero() {
        let z = FieldElement::ZERO;
        assert_eq!(z.neg(), FieldElement::ZERO);
    }

    #[test]
    fn test_inverse() {
        let a = FieldElement::from_u64(7);
        let inv_a = a.inv().unwrap();
        let product = a.mul(&inv_a);
        assert_eq!(product, FieldElement::ONE);
    }

    #[test]
    fn test_inverse_zero_returns_none() {
        assert!(FieldElement::ZERO.inv().is_none());
    }

    #[test]
    fn test_division() {
        let a = FieldElement::from_u64(42);
        let b = FieldElement::from_u64(7);
        let c = a.div(&b).unwrap();
        assert_eq!(c, FieldElement::from_u64(6));
    }

    #[test]
    fn test_division_by_zero_returns_none() {
        let a = FieldElement::from_u64(42);
        assert!(a.div(&FieldElement::ZERO).is_none());
    }

    #[test]
    fn test_pow() {
        let base = FieldElement::from_u64(2);
        let exp = [10, 0, 0, 0]; // 2^10 = 1024
        let result = base.pow(&exp);
        assert_eq!(result.to_canonical(), [1024, 0, 0, 0]);
    }

    #[test]
    fn test_from_i64_negative() {
        let a = FieldElement::from_i64(-1);
        // -1 mod p = p - 1
        assert_eq!(a, FieldElement::from_u64(0).sub(&FieldElement::ONE));
    }

    #[test]
    fn test_decimal_string_roundtrip() {
        let fe = FieldElement::from_u64(123456789);
        assert_eq!(fe.to_decimal_string(), "123456789");
    }

    #[test]
    fn test_from_decimal_str() {
        let fe = FieldElement::from_decimal_str("42").unwrap();
        assert_eq!(fe, FieldElement::from_u64(42));
    }

    #[test]
    fn test_from_hex_str() {
        let fe = FieldElement::from_hex_str("0x2a").unwrap();
        assert_eq!(fe, FieldElement::from_u64(42));

        let fe2 = FieldElement::from_hex_str("ff").unwrap();
        assert_eq!(fe2, FieldElement::from_u64(255));
    }

    #[test]
    fn test_from_binary_str() {
        let fe = FieldElement::from_binary_str("101010").unwrap();
        assert_eq!(fe, FieldElement::from_u64(42));

        let fe2 = FieldElement::from_binary_str("0").unwrap();
        assert_eq!(fe2, FieldElement::ZERO);

        let fe3 = FieldElement::from_binary_str("1").unwrap();
        assert_eq!(fe3, FieldElement::ONE);

        let fe4 = FieldElement::from_binary_str("11111111").unwrap();
        assert_eq!(fe4, FieldElement::from_u64(255));

        // Invalid chars
        assert!(FieldElement::from_binary_str("102").is_none());
        assert!(FieldElement::from_binary_str("abc").is_none());

        // Empty
        assert!(FieldElement::from_binary_str("").is_none());

        // Max 256 chars is ok
        let s256 = "1".repeat(256);
        assert!(FieldElement::from_binary_str(&s256).is_some());

        // 257 chars is too long
        let s257 = "1".repeat(257);
        assert!(FieldElement::from_binary_str(&s257).is_none());
    }

    #[test]
    fn test_multiplicative_identity() {
        let a = FieldElement::from_u64(12345);
        assert_eq!(a.mul(&FieldElement::ONE), a);
        assert_eq!(FieldElement::ONE.mul(&a), a);
    }

    #[test]
    fn test_additive_identity() {
        let a = FieldElement::from_u64(12345);
        assert_eq!(a.add(&FieldElement::ZERO), a);
    }

    #[test]
    fn test_display() {
        let fe = FieldElement::from_u64(42);
        assert_eq!(format!("{}", fe), "42");
    }

    #[test]
    fn test_to_le_bytes_zero() {
        assert_eq!(FieldElement::ZERO.to_le_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_to_le_bytes_one() {
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(FieldElement::ONE.to_le_bytes(), expected);
    }

    #[test]
    fn test_le_bytes_roundtrip() {
        for &val in &[0u64, 1, 42, 1000, u64::MAX] {
            let fe = FieldElement::from_u64(val);
            let bytes = fe.to_le_bytes();
            let recovered = FieldElement::from_le_bytes(&bytes).expect("valid field element");
            assert_eq!(fe, recovered);
        }
    }

    #[test]
    fn test_from_le_bytes_rejects_gte_modulus() {
        // p itself should be rejected
        let mut p_bytes = [0u8; 32];
        for i in 0..4 {
            p_bytes[i * 8..(i + 1) * 8].copy_from_slice(&MODULUS[i].to_le_bytes());
        }
        assert!(
            FieldElement::from_le_bytes(&p_bytes).is_none(),
            "p should be rejected"
        );

        // p + 1 should be rejected
        let mut p_plus_1 = p_bytes;
        p_plus_1[0] = p_plus_1[0].wrapping_add(1);
        assert!(
            FieldElement::from_le_bytes(&p_plus_1).is_none(),
            "p+1 should be rejected"
        );

        // all 0xFF bytes (max 256-bit value)
        let max_bytes = [0xFF; 32];
        assert!(
            FieldElement::from_le_bytes(&max_bytes).is_none(),
            "2^256-1 should be rejected"
        );

        // p - 1 should be accepted (largest valid element)
        let mut p_minus_1 = p_bytes;
        p_minus_1[0] = p_minus_1[0].wrapping_sub(1);
        assert!(
            FieldElement::from_le_bytes(&p_minus_1).is_some(),
            "p-1 should be accepted"
        );
    }

    // ========================================================================
    // External cryptographic test vectors (verified against Python pow()/mod)
    // ========================================================================

    #[test]
    fn test_vector_inv7() {
        // 7^(-1) mod p = 3126891838834182174606629392179610726935480628630862049099743455225115499374
        let seven = FieldElement::from_u64(7);
        let inv = seven.inv().unwrap();
        let expected = FieldElement::from_decimal_str(
            "3126891838834182174606629392179610726935480628630862049099743455225115499374",
        )
        .unwrap();
        assert_eq!(inv, expected, "inv(7) mismatch with reference vector");
        // Cross-check: 7 * inv(7) = 1
        assert_eq!(seven.mul(&inv), FieldElement::ONE);
    }

    #[test]
    fn test_vector_add_near_overflow() {
        // (p-1) + (p-1) mod p = p - 2
        let p_minus_1 = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let result = p_minus_1.add(&p_minus_1);
        let expected = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495615",
        )
        .unwrap();
        assert_eq!(result, expected, "(p-1)+(p-1) should be p-2");
    }

    #[test]
    fn test_vector_large_mul() {
        // 123456789 * 987654321 mod p = 121932631112635269
        let a = FieldElement::from_u64(123456789);
        let b = FieldElement::from_u64(987654321);
        let result = a.mul(&b);
        let expected = FieldElement::from_decimal_str("121932631112635269").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_vector_negation_one() {
        // 0 - 1 mod p = p - 1
        let result = FieldElement::ZERO.sub(&FieldElement::ONE);
        let expected = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        assert_eq!(result, expected, "0 - 1 should be p - 1");
    }

    #[test]
    fn test_vector_p_minus_1_squared() {
        // (p-1) * (p-1) mod p = 1, because (-1)^2 = 1
        let p_minus_1 = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let result = p_minus_1.mul(&p_minus_1);
        assert_eq!(result, FieldElement::ONE, "(-1)*(-1) should be 1");
    }

    #[test]
    fn test_vector_pow_42_10() {
        // 42^10 mod p = 17080198121677824
        let base = FieldElement::from_u64(42);
        let result = base.pow(&[10, 0, 0, 0]);
        let expected = FieldElement::from_decimal_str("17080198121677824").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_vector_large_limb_mul() {
        // (2^128 + 1) * (2^128 + 3) mod p — exercises multi-limb multiplication
        let a = FieldElement::from_decimal_str("340282366920938463463374607431768211457").unwrap(); // 2^128+1
        let b = FieldElement::from_decimal_str("340282366920938463463374607431768211459").unwrap(); // 2^128+3
        let result = a.mul(&b);
        let expected = FieldElement::from_decimal_str(
            "6350874878119819312338956282401532411889292131244146174820061504761160007678",
        )
        .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_montgomery_reduce_reference() {
        // Reference: montgomery_reduce(T) = T · R⁻¹ mod p
        // T = R (padded to 8 limbs) → result should be 1 (canonical)
        assert_eq!(
            montgomery_reduce(&[R[0], R[1], R[2], R[3], 0, 0, 0, 0]),
            [1, 0, 0, 0],
            "reduce(R) must be 1"
        );
        // T = R² (padded) → result should be R (Montgomery form of 1·R)
        let r2_wide = mul_wide(&R, &R);
        assert_eq!(montgomery_reduce(&r2_wide), R, "reduce(R²) must be R");
        // Cross-check: mul(a, R²) then reduce must yield a·R mod p (to_montgomery)
        // from_u64(42) uses this path internally; verify roundtrip
        let fe42 = FieldElement::from_u64(42);
        assert_eq!(fe42.to_canonical()[0], 42);
    }

    #[test]
    fn test_from_decimal_str_overflow_2_256_plus_1() {
        // 2^256 + 1 — previously produced wrong result (1) due to carry overflow
        let input =
            "115792089237316195423570985008687907853269984665640564039457584007913129639937";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        // Expected: (2^256 + 1) mod p
        // 2^256 mod p = R constant, so (2^256 + 1) mod p = R + 1 in canonical form
        // But we need to compute it properly: 2^256 mod p + 1
        let two_256_mod_p = FieldElement::from_canonical(R);
        let expected = two_256_mod_p.add(&FieldElement::ONE);
        assert_eq!(
            fe, expected,
            "from_decimal_str(2^256 + 1) should be correct"
        );
    }

    #[test]
    fn test_from_decimal_str_overflow_2_257() {
        // 2^257 = 2 * 2^256
        let input =
            "231584178474632390847141970017375815706539969331281128078915168015826259279872";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        // Expected: 2 * (2^256 mod p) mod p
        let two_256_mod_p = FieldElement::from_canonical(R);
        let two = FieldElement::from_u64(2);
        let expected = two_256_mod_p.mul(&two);
        assert_eq!(fe, expected, "from_decimal_str(2^257) should be correct");
    }

    #[test]
    fn test_from_decimal_str_very_large() {
        // 10^100 — a 101-digit number, well beyond 2^256
        let input = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        // Verify roundtrip: from_decimal_str → to_decimal_string → from_decimal_str
        let decimal = fe.to_decimal_string();
        let fe2 = FieldElement::from_decimal_str(&decimal).unwrap();
        assert_eq!(fe, fe2, "very large decimal should roundtrip");
    }

    #[test]
    fn test_from_decimal_str_exactly_p() {
        // Input = p itself → should yield 0
        let p_str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        let fe = FieldElement::from_decimal_str(p_str).unwrap();
        assert_eq!(fe, FieldElement::ZERO, "p mod p should be 0");
    }

    #[test]
    fn test_from_decimal_str_p_plus_1() {
        // Input = p + 1 → should yield 1
        let p_plus_1 =
            "21888242871839275222246405745257275088548364400416034343698204186575808495618";
        let fe = FieldElement::from_decimal_str(p_plus_1).unwrap();
        assert_eq!(fe, FieldElement::ONE, "p + 1 mod p should be 1");
    }

    #[test]
    fn test_vector_montgomery_r() {
        // 2^256 mod p = R constant = 6350874878119819312338956282401532410528162663560392320966563075034087161851
        let r_expected = FieldElement::from_decimal_str(
            "6350874878119819312338956282401532410528162663560392320966563075034087161851",
        )
        .unwrap();
        assert_eq!(
            r_expected.to_canonical(),
            R,
            "R constant must match 2^256 mod p"
        );
    }
}
