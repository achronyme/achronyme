/// Prime Field Element — backed by `FieldBackend`.
///
/// Currently hardwired to `Bn254Fr`. The `FieldBackend` trait and `Bn254Fr`
/// backend are in place; Phase 2 of the multi-prime migration will make
/// `FieldElement` generic over the backend. Until then, the concrete struct
/// delegates to `Bn254Fr` internally, proving the abstraction works.
pub(crate) mod arithmetic;
mod backend;
pub mod bn254;
mod prime_id;

pub use arithmetic::MODULUS;
pub use backend::FieldBackend;
pub use bn254::Bn254Fr;
pub use prime_id::PrimeId;

/// A BN254 scalar field element.
///
/// Internally delegates all operations to the `Bn254Fr` backend.
/// This struct will become `FieldElement<F: FieldBackend>` in Phase 2.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldElement {
    /// Internal representation (Montgomery form [u64; 4]).
    pub(crate) repr: <Bn254Fr as FieldBackend>::Repr,
}

impl FieldElement {
    /// Wrap a raw backend representation.
    #[inline]
    pub(crate) fn from_repr(repr: <Bn254Fr as FieldBackend>::Repr) -> Self {
        Self { repr }
    }
}

// Custom serde: delegates to Bn254Fr backend.
impl serde::Serialize for FieldElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Bn254Fr::serde_serialize(&self.repr, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for FieldElement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Bn254Fr::serde_deserialize(deserializer).map(Self::from_repr)
    }
}

// ============================================================================
// FieldElement public API — delegates to Bn254Fr backend
// ============================================================================

impl FieldElement {
    /// Number of 64-bit limbs in the internal representation.
    pub const NUM_LIMBS: usize = 4;

    /// The zero element (0 in Montgomery form = 0).
    pub const ZERO: Self = Self { repr: [0; 4] };

    /// The one element (1 in Montgomery form = R mod p).
    pub const ONE: Self = Self {
        repr: arithmetic::R,
    };

    /// Which prime field this element belongs to.
    pub const fn prime_id() -> PrimeId {
        Bn254Fr::PRIME_ID
    }

    /// Create from a small u64 value.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_u64(42);
    /// assert_eq!(fe.to_canonical(), [42, 0, 0, 0]);
    /// ```
    pub fn from_u64(val: u64) -> Self {
        Self::from_repr(Bn254Fr::from_u64(val))
    }

    /// Create from a signed i64 value.
    pub fn from_i64(val: i64) -> Self {
        Self::from_repr(Bn254Fr::from_i64(val))
    }

    /// Create from canonical form [u64; 4] (already reduced mod p).
    pub fn from_canonical(limbs: [u64; 4]) -> Self {
        Self::from_repr(Bn254Fr::from_canonical_limbs(&limbs))
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
        Bn254Fr::to_canonical_limbs(&self.repr)
    }

    /// Check if zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        Bn254Fr::is_zero(&self.repr)
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
        Self::from_repr(Bn254Fr::add(&self.repr, &other.repr))
    }

    /// Modular subtraction: (self - other) mod p (constant-time).
    pub fn sub(&self, other: &Self) -> Self {
        Self::from_repr(Bn254Fr::sub(&self.repr, &other.repr))
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
        Self::from_repr(Bn254Fr::mul(&self.repr, &other.repr))
    }

    /// Modular negation: (-self) mod p (constant-time).
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let a = FieldElement::from_u64(5);
    /// assert!(a.add(&a.neg()).is_zero());
    /// assert_eq!(FieldElement::ZERO.neg(), FieldElement::ZERO);
    /// ```
    pub fn neg(&self) -> Self {
        Self::from_repr(Bn254Fr::neg(&self.repr))
    }

    /// Modular inverse: self⁻¹ mod p via Fermat's little theorem.
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
        Bn254Fr::inv(&self.repr).map(Self::from_repr)
    }

    /// Modular division: self / other mod p. Returns None if other is zero.
    pub fn div(&self, other: &Self) -> Option<Self> {
        Some(self.mul(&other.inv()?))
    }

    /// Modular exponentiation: self^exp mod p (constant-time).
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        Self::from_repr(Bn254Fr::pow(&self.repr, exp))
    }

    /// Serialize to canonical little-endian bytes (32 bytes).
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_u64(42);
    /// let bytes = fe.to_le_bytes();
    /// let recovered = FieldElement::from_le_bytes(&bytes).unwrap();
    /// assert_eq!(fe, recovered);
    /// ```
    pub fn to_le_bytes(&self) -> [u8; 32] {
        Bn254Fr::to_le_bytes(&self.repr)
    }

    /// Deserialize from canonical little-endian bytes.
    /// Returns `None` if the value is >= the BN254 prime modulus.
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Bn254Fr::from_le_bytes(bytes).map(Self::from_repr)
    }

    /// Display as canonical decimal string.
    pub fn to_decimal_string(&self) -> String {
        Bn254Fr::to_decimal_string(&self.repr)
    }

    /// Parse from decimal string.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_decimal_str("123456789").unwrap();
    /// assert_eq!(fe.to_decimal_string(), "123456789");
    /// ```
    pub fn from_decimal_str(s: &str) -> Option<Self> {
        Bn254Fr::from_decimal_str(s).map(Self::from_repr)
    }

    /// Parse from hex string (with or without "0x" prefix).
    pub fn from_hex_str(s: &str) -> Option<Self> {
        Bn254Fr::from_hex_str(s).map(Self::from_repr)
    }

    /// Parse from binary string ('0'/'1' chars only, max 256 chars).
    pub fn from_binary_str(s: &str) -> Option<Self> {
        Bn254Fr::from_binary_str(s).map(Self::from_repr)
    }

    /// The prime modulus as little-endian bytes.
    pub fn modulus_le_bytes() -> [u8; 32] {
        Bn254Fr::modulus_le_bytes()
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
    use arithmetic::*;

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

        let two_256 = num_bigint::BigUint::one() << 256;
        assert_eq!(limbs_to_bigint(&R), &two_256 % &p, "R constant is wrong");

        let r = &two_256 % &p;
        assert_eq!(limbs_to_bigint(&R2), (&r * &r) % &p, "R2 constant is wrong");

        assert_eq!(MODULUS[0].wrapping_mul(INV), u64::MAX);

        assert_eq!(
            montgomery_reduce(&[R[0], R[1], R[2], R[3], 0, 0, 0, 0]),
            [1, 0, 0, 0]
        );

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
    fn test_prime_id() {
        assert_eq!(FieldElement::prime_id(), PrimeId::Bn254);
    }

    #[test]
    fn test_from_u64_roundtrip() {
        for &val in &[0u64, 1, 2, 42, 1000, u64::MAX] {
            let fe = FieldElement::from_u64(val);
            let canonical = fe.to_canonical();
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
        let exp = [10, 0, 0, 0];
        let result = base.pow(&exp);
        assert_eq!(result.to_canonical(), [1024, 0, 0, 0]);
    }

    #[test]
    fn test_from_i64_negative() {
        let a = FieldElement::from_i64(-1);
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

        assert!(FieldElement::from_binary_str("102").is_none());
        assert!(FieldElement::from_binary_str("abc").is_none());
        assert!(FieldElement::from_binary_str("").is_none());

        let s256 = "1".repeat(256);
        assert!(FieldElement::from_binary_str(&s256).is_some());

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
        let mut p_bytes = [0u8; 32];
        for i in 0..4 {
            p_bytes[i * 8..(i + 1) * 8].copy_from_slice(&MODULUS[i].to_le_bytes());
        }
        assert!(
            FieldElement::from_le_bytes(&p_bytes).is_none(),
            "p should be rejected"
        );

        let mut p_plus_1 = p_bytes;
        p_plus_1[0] = p_plus_1[0].wrapping_add(1);
        assert!(
            FieldElement::from_le_bytes(&p_plus_1).is_none(),
            "p+1 should be rejected"
        );

        let max_bytes = [0xFF; 32];
        assert!(
            FieldElement::from_le_bytes(&max_bytes).is_none(),
            "2^256-1 should be rejected"
        );

        let mut p_minus_1 = p_bytes;
        p_minus_1[0] = p_minus_1[0].wrapping_sub(1);
        assert!(
            FieldElement::from_le_bytes(&p_minus_1).is_some(),
            "p-1 should be accepted"
        );
    }

    // ========================================================================
    // External cryptographic test vectors
    // ========================================================================

    #[test]
    fn test_vector_inv7() {
        let seven = FieldElement::from_u64(7);
        let inv = seven.inv().unwrap();
        let expected = FieldElement::from_decimal_str(
            "3126891838834182174606629392179610726935480628630862049099743455225115499374",
        )
        .unwrap();
        assert_eq!(inv, expected, "inv(7) mismatch with reference vector");
        assert_eq!(seven.mul(&inv), FieldElement::ONE);
    }

    #[test]
    fn test_vector_add_near_overflow() {
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
        let a = FieldElement::from_u64(123456789);
        let b = FieldElement::from_u64(987654321);
        let result = a.mul(&b);
        let expected = FieldElement::from_decimal_str("121932631112635269").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_vector_negation_one() {
        let result = FieldElement::ZERO.sub(&FieldElement::ONE);
        let expected = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        assert_eq!(result, expected, "0 - 1 should be p - 1");
    }

    #[test]
    fn test_vector_p_minus_1_squared() {
        let p_minus_1 = FieldElement::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let result = p_minus_1.mul(&p_minus_1);
        assert_eq!(result, FieldElement::ONE, "(-1)*(-1) should be 1");
    }

    #[test]
    fn test_vector_pow_42_10() {
        let base = FieldElement::from_u64(42);
        let result = base.pow(&[10, 0, 0, 0]);
        let expected = FieldElement::from_decimal_str("17080198121677824").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_vector_large_limb_mul() {
        let a = FieldElement::from_decimal_str("340282366920938463463374607431768211457").unwrap();
        let b = FieldElement::from_decimal_str("340282366920938463463374607431768211459").unwrap();
        let result = a.mul(&b);
        let expected = FieldElement::from_decimal_str(
            "6350874878119819312338956282401532411889292131244146174820061504761160007678",
        )
        .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_montgomery_reduce_reference() {
        assert_eq!(
            montgomery_reduce(&[R[0], R[1], R[2], R[3], 0, 0, 0, 0]),
            [1, 0, 0, 0],
            "reduce(R) must be 1"
        );
        let r2_wide = mul_wide(&R, &R);
        assert_eq!(montgomery_reduce(&r2_wide), R, "reduce(R²) must be R");
        let fe42 = FieldElement::from_u64(42);
        assert_eq!(fe42.to_canonical()[0], 42);
    }

    #[test]
    fn test_from_decimal_str_overflow_2_256_plus_1() {
        let input =
            "115792089237316195423570985008687907853269984665640564039457584007913129639937";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        let two_256_mod_p = FieldElement::from_canonical(R);
        let expected = two_256_mod_p.add(&FieldElement::ONE);
        assert_eq!(
            fe, expected,
            "from_decimal_str(2^256 + 1) should be correct"
        );
    }

    #[test]
    fn test_from_decimal_str_overflow_2_257() {
        let input =
            "231584178474632390847141970017375815706539969331281128078915168015826259279872";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        let two_256_mod_p = FieldElement::from_canonical(R);
        let two = FieldElement::from_u64(2);
        let expected = two_256_mod_p.mul(&two);
        assert_eq!(fe, expected, "from_decimal_str(2^257) should be correct");
    }

    #[test]
    fn test_from_decimal_str_very_large() {
        let input = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let fe = FieldElement::from_decimal_str(input).unwrap();
        let decimal = fe.to_decimal_string();
        let fe2 = FieldElement::from_decimal_str(&decimal).unwrap();
        assert_eq!(fe, fe2, "very large decimal should roundtrip");
    }

    #[test]
    fn test_from_decimal_str_exactly_p() {
        let p_str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        let fe = FieldElement::from_decimal_str(p_str).unwrap();
        assert_eq!(fe, FieldElement::ZERO, "p mod p should be 0");
    }

    #[test]
    fn test_from_decimal_str_p_plus_1() {
        let p_plus_1 =
            "21888242871839275222246405745257275088548364400416034343698204186575808495618";
        let fe = FieldElement::from_decimal_str(p_plus_1).unwrap();
        assert_eq!(fe, FieldElement::ONE, "p + 1 mod p should be 1");
    }

    #[test]
    fn test_from_decimal_str_zero() {
        let fe = FieldElement::from_decimal_str("0").unwrap();
        assert_eq!(fe, FieldElement::ZERO);
    }

    #[test]
    fn test_from_decimal_str_empty_string() {
        assert!(
            FieldElement::from_decimal_str("").is_none(),
            "empty string should return None"
        );
    }

    #[test]
    fn test_from_decimal_str_invalid_chars() {
        assert!(FieldElement::from_decimal_str("abc").is_none());
        assert!(FieldElement::from_decimal_str("12x4").is_none());
        assert!(FieldElement::from_decimal_str("-1").is_none());
        assert!(FieldElement::from_decimal_str("1.5").is_none());
        assert!(FieldElement::from_decimal_str(" 42").is_none());
    }

    #[test]
    fn test_vector_montgomery_r() {
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
