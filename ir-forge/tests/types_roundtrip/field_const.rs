use super::*;

#[test]
fn field_const_from_decimal_small() {
    let fc = FieldConst::from_decimal_str("42").unwrap();
    assert_eq!(fc, FieldConst::from_u64(42));
}

#[test]
fn field_const_from_decimal_zero() {
    let fc = FieldConst::from_decimal_str("0").unwrap();
    assert_eq!(fc, FieldConst::zero());
}

#[test]
fn field_const_from_decimal_large() {
    // BN254 field order - 1 (a ~77 digit number)
    let s = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    let fc = FieldConst::from_decimal_str(s).unwrap();
    // Should not be zero and should not fit in u64
    assert!(!fc.is_zero());
    assert!(fc.to_u64().is_none());
}

#[test]
fn field_const_from_decimal_max_u64() {
    let fc = FieldConst::from_decimal_str("18446744073709551615").unwrap();
    assert_eq!(fc, FieldConst::from_u64(u64::MAX));
}

#[test]
fn field_const_from_decimal_just_above_u64() {
    let fc = FieldConst::from_decimal_str("18446744073709551616").unwrap();
    assert!(fc.to_u64().is_none());
    // Verify byte 8 is 1 (2^64 = 1 in byte[8])
    assert_eq!(fc.bytes()[8], 1);
}

#[test]
fn field_const_from_decimal_invalid() {
    assert!(FieldConst::from_decimal_str("").is_none());
    assert!(FieldConst::from_decimal_str("abc").is_none());
    assert!(FieldConst::from_decimal_str("12x3").is_none());
}

#[test]
fn field_const_from_hex_small() {
    let fc = FieldConst::from_hex_str("0xFF").unwrap();
    assert_eq!(fc, FieldConst::from_u64(255));
}

#[test]
fn field_const_from_hex_no_prefix() {
    let fc = FieldConst::from_hex_str("ff").unwrap();
    assert_eq!(fc, FieldConst::from_u64(255));
}

#[test]
fn field_const_from_hex_large() {
    // 64 hex digits = 32 bytes (max)
    let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    let fc = FieldConst::from_hex_str(hex).unwrap();
    assert!(!fc.is_zero());
    assert!(fc.to_u64().is_none());
}

#[test]
fn field_const_from_hex_with_0x_prefix() {
    let fc = FieldConst::from_hex_str("0x1234").unwrap();
    assert_eq!(fc, FieldConst::from_u64(0x1234));
}

#[test]
fn field_const_from_hex_invalid() {
    assert!(FieldConst::from_hex_str("").is_none());
    assert!(FieldConst::from_hex_str("0x").is_none());
    assert!(FieldConst::from_hex_str("0xGG").is_none());
    // 65 hex digits = too large
    let too_large = "1".to_string() + &"0".repeat(64);
    assert!(FieldConst::from_hex_str(&too_large).is_none());
}
