use super::arithmetic::*;
use super::*;

// Type alias for brevity — resolves inference in standalone expressions
type FE = FieldElement;

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
    assert!(FE::ZERO.is_zero());
    assert!(!FE::ONE.is_zero());
    assert_eq!(FE::ONE.to_canonical(), [1, 0, 0, 0]);
    assert_eq!(FE::ZERO.to_canonical(), [0, 0, 0, 0]);
}

#[test]
fn test_zero_one_consistency() {
    assert_eq!(FE::ZERO, FE::zero());
    assert_eq!(FE::ONE, FE::one());
}

#[test]
fn test_prime_id() {
    assert_eq!(FE::prime_id(), PrimeId::Bn254);
}

#[test]
fn test_from_u64_roundtrip() {
    for &val in &[0u64, 1, 2, 42, 1000, u64::MAX] {
        let fe = FE::from_u64(val);
        let canonical = fe.to_canonical();
        assert_eq!(canonical[0], val);
        assert_eq!(canonical[1], 0);
        assert_eq!(canonical[2], 0);
        assert_eq!(canonical[3], 0);
    }
}

#[test]
fn test_addition() {
    let a = FE::from_u64(7);
    let b = FE::from_u64(5);
    let c = a.add(&b);
    assert_eq!(c.to_canonical(), [12, 0, 0, 0]);
}

#[test]
fn test_subtraction() {
    let a = FE::from_u64(10);
    let b = FE::from_u64(3);
    let c = a.sub(&b);
    assert_eq!(c.to_canonical(), [7, 0, 0, 0]);
}

#[test]
fn test_subtraction_underflow() {
    let a = FE::from_u64(3);
    let b = FE::from_u64(10);
    let c = a.sub(&b);
    let expected = FE::from_u64(0).sub(&FE::from_u64(7));
    assert_eq!(c, expected);
}

#[test]
fn test_multiplication() {
    let a = FE::from_u64(6);
    let b = FE::from_u64(7);
    let c = a.mul(&b);
    assert_eq!(c.to_canonical(), [42, 0, 0, 0]);
}

#[test]
fn test_negation() {
    let a = FE::from_u64(5);
    let neg_a = a.neg();
    let sum = a.add(&neg_a);
    assert!(sum.is_zero());
}

#[test]
fn test_negation_zero() {
    let z = FE::ZERO;
    assert_eq!(z.neg(), FE::ZERO);
}

#[test]
fn test_inverse() {
    let a = FE::from_u64(7);
    let inv_a = a.inv().unwrap();
    let product = a.mul(&inv_a);
    assert_eq!(product, FE::ONE);
}

#[test]
fn test_inverse_zero_returns_none() {
    assert!(FE::ZERO.inv().is_none());
}

#[test]
fn test_division() {
    let a = FE::from_u64(42);
    let b = FE::from_u64(7);
    let c = a.div(&b).unwrap();
    assert_eq!(c, FE::from_u64(6));
}

#[test]
fn test_division_by_zero_returns_none() {
    let a = FE::from_u64(42);
    assert!(a.div(&FE::ZERO).is_none());
}

#[test]
fn test_pow() {
    let base = FE::from_u64(2);
    let exp = [10, 0, 0, 0];
    let result = base.pow(&exp);
    assert_eq!(result.to_canonical(), [1024, 0, 0, 0]);
}

#[test]
fn test_from_i64_negative() {
    let a = FE::from_i64(-1);
    assert_eq!(a, FE::from_u64(0).sub(&FE::ONE));
}

#[test]
fn test_decimal_string_roundtrip() {
    let fe = FE::from_u64(123456789);
    assert_eq!(fe.to_decimal_string(), "123456789");
}

#[test]
fn test_from_decimal_str() {
    let fe = FE::from_decimal_str("42").unwrap();
    assert_eq!(fe, FE::from_u64(42));
}

#[test]
fn test_from_hex_str() {
    let fe = FE::from_hex_str("0x2a").unwrap();
    assert_eq!(fe, FE::from_u64(42));

    let fe2 = FE::from_hex_str("ff").unwrap();
    assert_eq!(fe2, FE::from_u64(255));
}

#[test]
fn test_from_binary_str() {
    let fe = FE::from_binary_str("101010").unwrap();
    assert_eq!(fe, FE::from_u64(42));

    let fe2 = FE::from_binary_str("0").unwrap();
    assert_eq!(fe2, FE::ZERO);

    let fe3 = FE::from_binary_str("1").unwrap();
    assert_eq!(fe3, FE::ONE);

    let fe4 = FE::from_binary_str("11111111").unwrap();
    assert_eq!(fe4, FE::from_u64(255));

    assert!(FE::from_binary_str("102").is_none());
    assert!(FE::from_binary_str("abc").is_none());
    assert!(FE::from_binary_str("").is_none());

    let s256 = "1".repeat(256);
    assert!(FE::from_binary_str(&s256).is_some());

    let s257 = "1".repeat(257);
    assert!(FE::from_binary_str(&s257).is_none());
}

#[test]
fn test_multiplicative_identity() {
    let a = FE::from_u64(12345);
    assert_eq!(a.mul(&FE::ONE), a);
    assert_eq!(FE::ONE.mul(&a), a);
}

#[test]
fn test_additive_identity() {
    let a = FE::from_u64(12345);
    assert_eq!(a.add(&FE::ZERO), a);
}

#[test]
fn test_display() {
    let fe = FE::from_u64(42);
    assert_eq!(format!("{}", fe), "42");
}

#[test]
fn test_to_le_bytes_zero() {
    assert_eq!(FE::ZERO.to_le_bytes(), [0u8; 32]);
}

#[test]
fn test_to_le_bytes_one() {
    let mut expected = [0u8; 32];
    expected[0] = 1;
    assert_eq!(FE::ONE.to_le_bytes(), expected);
}

#[test]
fn test_le_bytes_roundtrip() {
    for &val in &[0u64, 1, 42, 1000, u64::MAX] {
        let fe = FE::from_u64(val);
        let bytes = fe.to_le_bytes();
        let recovered = FE::from_le_bytes(&bytes).expect("valid field element");
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
        FE::from_le_bytes(&p_bytes).is_none(),
        "p should be rejected"
    );

    let mut p_plus_1 = p_bytes;
    p_plus_1[0] = p_plus_1[0].wrapping_add(1);
    assert!(
        FE::from_le_bytes(&p_plus_1).is_none(),
        "p+1 should be rejected"
    );

    let max_bytes = [0xFF; 32];
    assert!(
        FE::from_le_bytes(&max_bytes).is_none(),
        "2^256-1 should be rejected"
    );

    let mut p_minus_1 = p_bytes;
    p_minus_1[0] = p_minus_1[0].wrapping_sub(1);
    assert!(
        FE::from_le_bytes(&p_minus_1).is_some(),
        "p-1 should be accepted"
    );
}

// ============================================================================
// External cryptographic test vectors
// ============================================================================

#[test]
fn test_vector_inv7() {
    let seven = FE::from_u64(7);
    let inv = seven.inv().unwrap();
    let expected = FE::from_decimal_str(
        "3126891838834182174606629392179610726935480628630862049099743455225115499374",
    )
    .unwrap();
    assert_eq!(inv, expected, "inv(7) mismatch with reference vector");
    assert_eq!(seven.mul(&inv), FE::ONE);
}

#[test]
fn test_vector_add_near_overflow() {
    let p_minus_1 = FE::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap();
    let result = p_minus_1.add(&p_minus_1);
    let expected = FE::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495615",
    )
    .unwrap();
    assert_eq!(result, expected, "(p-1)+(p-1) should be p-2");
}

#[test]
fn test_vector_large_mul() {
    let a = FE::from_u64(123456789);
    let b = FE::from_u64(987654321);
    let result = a.mul(&b);
    let expected = FE::from_decimal_str("121932631112635269").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_vector_negation_one() {
    let result = FE::ZERO.sub(&FE::ONE);
    let expected = FE::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap();
    assert_eq!(result, expected, "0 - 1 should be p - 1");
}

#[test]
fn test_vector_p_minus_1_squared() {
    let p_minus_1 = FE::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap();
    let result = p_minus_1.mul(&p_minus_1);
    assert_eq!(result, FE::ONE, "(-1)*(-1) should be 1");
}

#[test]
fn test_vector_pow_42_10() {
    let base = FE::from_u64(42);
    let result = base.pow(&[10, 0, 0, 0]);
    let expected = FE::from_decimal_str("17080198121677824").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_vector_large_limb_mul() {
    let a = FE::from_decimal_str("340282366920938463463374607431768211457").unwrap();
    let b = FE::from_decimal_str("340282366920938463463374607431768211459").unwrap();
    let result = a.mul(&b);
    let expected = FE::from_decimal_str(
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
    let fe42 = FE::from_u64(42);
    assert_eq!(fe42.to_canonical()[0], 42);
}

#[test]
fn test_from_decimal_str_overflow_2_256_plus_1() {
    let input = "115792089237316195423570985008687907853269984665640564039457584007913129639937";
    let fe = FE::from_decimal_str(input).unwrap();
    let two_256_mod_p = FE::from_canonical(R);
    let expected = two_256_mod_p.add(&FE::ONE);
    assert_eq!(
        fe, expected,
        "from_decimal_str(2^256 + 1) should be correct"
    );
}

#[test]
fn test_from_decimal_str_overflow_2_257() {
    let input = "231584178474632390847141970017375815706539969331281128078915168015826259279872";
    let fe = FE::from_decimal_str(input).unwrap();
    let two_256_mod_p = FE::from_canonical(R);
    let two = FE::from_u64(2);
    let expected = two_256_mod_p.mul(&two);
    assert_eq!(fe, expected, "from_decimal_str(2^257) should be correct");
}

#[test]
fn test_from_decimal_str_very_large() {
    let input = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let fe = FE::from_decimal_str(input).unwrap();
    let decimal = fe.to_decimal_string();
    let fe2 = FE::from_decimal_str(&decimal).unwrap();
    assert_eq!(fe, fe2, "very large decimal should roundtrip");
}

#[test]
fn test_from_decimal_str_exactly_p() {
    let p_str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    let fe = FE::from_decimal_str(p_str).unwrap();
    assert_eq!(fe, FE::ZERO, "p mod p should be 0");
}

#[test]
fn test_from_decimal_str_p_plus_1() {
    let p_plus_1 = "21888242871839275222246405745257275088548364400416034343698204186575808495618";
    let fe = FE::from_decimal_str(p_plus_1).unwrap();
    assert_eq!(fe, FE::ONE, "p + 1 mod p should be 1");
}

#[test]
fn test_from_decimal_str_zero() {
    let fe = FE::from_decimal_str("0").unwrap();
    assert_eq!(fe, FE::ZERO);
}

#[test]
fn test_from_decimal_str_empty_string() {
    assert!(
        FE::from_decimal_str("").is_none(),
        "empty string should return None"
    );
}

#[test]
fn test_from_decimal_str_invalid_chars() {
    assert!(FE::from_decimal_str("abc").is_none());
    assert!(FE::from_decimal_str("12x4").is_none());
    assert!(FE::from_decimal_str("-1").is_none());
    assert!(FE::from_decimal_str("1.5").is_none());
    assert!(FE::from_decimal_str(" 42").is_none());
}

#[test]
fn test_vector_montgomery_r() {
    let r_expected = FE::from_decimal_str(
        "6350874878119819312338956282401532410528162663560392320966563075034087161851",
    )
    .unwrap();
    assert_eq!(
        r_expected.to_canonical(),
        R,
        "R constant must match 2^256 mod p"
    );
}
