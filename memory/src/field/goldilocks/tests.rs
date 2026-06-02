use super::arithmetic::*;
use super::*;
use crate::{FieldBackend, FieldElement, PrimeId};

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
