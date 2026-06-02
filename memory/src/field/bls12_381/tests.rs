use super::constants::INV;
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

    // INV: MODULUS[0] * INV == -1 (mod 2^64)
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
    let p_plus_1 = "52435875175126190479447740508185965837690552500527637822603658699938581184514";
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
