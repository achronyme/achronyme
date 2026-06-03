use super::*;

#[test]
fn validate_field_limbs_bn254_zero_ok() {
    assert!(validate_field_limbs([0, 0, 0, 0], PrimeId::Bn254));
}

#[test]
fn validate_field_limbs_bn254_one_ok() {
    assert!(validate_field_limbs([1, 0, 0, 0], PrimeId::Bn254));
}

#[test]
fn validate_field_limbs_bn254_modulus_rejected() {
    // BN254 modulus limbs
    let modulus = [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];
    assert!(!validate_field_limbs(modulus, PrimeId::Bn254));
}

#[test]
fn validate_field_limbs_bn254_modulus_minus_one_ok() {
    let modulus_minus_1 = [
        0x43e1f593f0000000, // l0 - 1
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];
    assert!(validate_field_limbs(modulus_minus_1, PrimeId::Bn254));
}

#[test]
fn validate_field_limbs_goldilocks_ok() {
    assert!(validate_field_limbs([42, 0, 0, 0], PrimeId::Goldilocks));
}

#[test]
fn validate_field_limbs_goldilocks_modulus_rejected() {
    // Goldilocks p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
    let p = 0xFFFFFFFF00000001u64;
    assert!(!validate_field_limbs([p, 0, 0, 0], PrimeId::Goldilocks));
}

#[test]
fn validate_field_limbs_goldilocks_nonzero_upper_rejected() {
    // l1 != 0 but l0 < p — still exceeds modulus because total > p
    assert!(!validate_field_limbs([0, 1, 0, 0], PrimeId::Goldilocks));
}
