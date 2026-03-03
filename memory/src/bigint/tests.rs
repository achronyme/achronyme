use super::*;

// --- Constructors ---

#[test]
fn test_zero() {
    let z256 = BigInt::zero(BigIntWidth::W256);
    assert!(z256.is_zero());
    assert_eq!(z256.num_limbs(), 4);
    assert_eq!(z256.width(), BigIntWidth::W256);

    let z512 = BigInt::zero(BigIntWidth::W512);
    assert!(z512.is_zero());
    assert_eq!(z512.num_limbs(), 8);
}

#[test]
fn test_one() {
    let one = BigInt::one(BigIntWidth::W256);
    assert!(!one.is_zero());
    assert_eq!(one.limbs()[0], 1);
}

#[test]
fn test_from_u64() {
    let b = BigInt::from_u64(42, BigIntWidth::W256);
    assert_eq!(b.limbs()[0], 42);
    assert_eq!(b.to_hex_string(), "2a");
}

#[test]
fn test_from_u64_max() {
    let b = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
    assert_eq!(b.limbs()[0], u64::MAX);
    assert_eq!(b.to_hex_string(), "ffffffffffffffff");
}

// --- Parsing ---

#[test]
fn test_from_hex_str() {
    let b = BigInt::from_hex_str("ff", BigIntWidth::W256).unwrap();
    assert_eq!(b, BigInt::from_u64(255, BigIntWidth::W256));

    let b2 = BigInt::from_hex_str("0x2a", BigIntWidth::W256).unwrap();
    assert_eq!(b2, BigInt::from_u64(42, BigIntWidth::W256));
}

#[test]
fn test_from_hex_str_large() {
    let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let b = BigInt::from_hex_str(hex, BigIntWidth::W256).unwrap();
    assert!(b.limbs().iter().all(|&l| l == u64::MAX));
}

#[test]
fn test_from_hex_str_too_long() {
    // 65 hex chars = 260 bits, too long for 256
    let hex = "1".to_string() + &"0".repeat(64);
    assert!(BigInt::from_hex_str(&hex, BigIntWidth::W256).is_none());
}

#[test]
fn test_from_decimal_str() {
    let b = BigInt::from_decimal_str("42", BigIntWidth::W256).unwrap();
    assert_eq!(b, BigInt::from_u64(42, BigIntWidth::W256));
}

#[test]
fn test_from_binary_str() {
    let b = BigInt::from_binary_str("101010", BigIntWidth::W256).unwrap();
    assert_eq!(b, BigInt::from_u64(42, BigIntWidth::W256));
}

#[test]
fn test_from_binary_str_invalid() {
    assert!(BigInt::from_binary_str("102", BigIntWidth::W256).is_none());
    assert!(BigInt::from_binary_str("", BigIntWidth::W256).is_none());
}

// --- Arithmetic ---

#[test]
fn test_add_basic() {
    let a = BigInt::from_u64(100, BigIntWidth::W256);
    let b = BigInt::from_u64(200, BigIntWidth::W256);
    let c = a.add(&b).unwrap();
    assert_eq!(c, BigInt::from_u64(300, BigIntWidth::W256));
}

#[test]
fn test_add_carry() {
    let a = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
    let b = BigInt::from_u64(1, BigIntWidth::W256);
    let c = a.add(&b).unwrap();
    assert_eq!(c.limbs()[0], 0);
    assert_eq!(c.limbs()[1], 1);
}

#[test]
fn test_add_overflow() {
    let max = BigInt::from_hex_str(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        BigIntWidth::W256,
    )
    .unwrap();
    let one = BigInt::one(BigIntWidth::W256);
    assert_eq!(max.add(&one), Err(BigIntError::Overflow));
}

#[test]
fn test_sub_basic() {
    let a = BigInt::from_u64(300, BigIntWidth::W256);
    let b = BigInt::from_u64(100, BigIntWidth::W256);
    assert_eq!(a.sub(&b).unwrap(), BigInt::from_u64(200, BigIntWidth::W256));
}

#[test]
fn test_sub_underflow() {
    let a = BigInt::from_u64(0, BigIntWidth::W256);
    let b = BigInt::from_u64(1, BigIntWidth::W256);
    assert_eq!(a.sub(&b), Err(BigIntError::Underflow));
}

#[test]
fn test_mul_basic() {
    let a = BigInt::from_u64(6, BigIntWidth::W256);
    let b = BigInt::from_u64(7, BigIntWidth::W256);
    assert_eq!(a.mul(&b).unwrap(), BigInt::from_u64(42, BigIntWidth::W256));
}

#[test]
fn test_mul_large() {
    let a = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
    let b = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
    let c = a.mul(&b).unwrap();
    // u64::MAX * u64::MAX = (2^64-1)^2 = 2^128 - 2^65 + 1
    assert_eq!(c.limbs()[0], 1);
    assert_eq!(c.limbs()[1], 0xfffffffffffffffe);
    assert_eq!(c.limbs()[2], 0);
}

#[test]
fn test_mul_overflow() {
    let max = BigInt::from_hex_str(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        BigIntWidth::W256,
    )
    .unwrap();
    let two = BigInt::from_u64(2, BigIntWidth::W256);
    assert_eq!(max.mul(&two), Err(BigIntError::Overflow));
}

#[test]
fn test_div_basic() {
    let a = BigInt::from_u64(42, BigIntWidth::W256);
    let b = BigInt::from_u64(7, BigIntWidth::W256);
    assert_eq!(a.div(&b).unwrap(), BigInt::from_u64(6, BigIntWidth::W256));
}

#[test]
fn test_div_truncates() {
    let a = BigInt::from_u64(10, BigIntWidth::W256);
    let b = BigInt::from_u64(3, BigIntWidth::W256);
    assert_eq!(a.div(&b).unwrap(), BigInt::from_u64(3, BigIntWidth::W256));
}

#[test]
fn test_div_by_zero() {
    let a = BigInt::from_u64(42, BigIntWidth::W256);
    let z = BigInt::zero(BigIntWidth::W256);
    assert_eq!(a.div(&z), Err(BigIntError::DivisionByZero));
}

#[test]
fn test_modulo() {
    let a = BigInt::from_u64(10, BigIntWidth::W256);
    let b = BigInt::from_u64(3, BigIntWidth::W256);
    assert_eq!(
        a.modulo(&b).unwrap(),
        BigInt::from_u64(1, BigIntWidth::W256)
    );
}

// --- Bitwise ---

#[test]
fn test_bit_and() {
    let a = BigInt::from_u64(0xFF, BigIntWidth::W256);
    let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
    assert_eq!(
        a.bit_and(&b).unwrap(),
        BigInt::from_u64(0x0F, BigIntWidth::W256)
    );
}

#[test]
fn test_bit_or() {
    let a = BigInt::from_u64(0xF0, BigIntWidth::W256);
    let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
    assert_eq!(
        a.bit_or(&b).unwrap(),
        BigInt::from_u64(0xFF, BigIntWidth::W256)
    );
}

#[test]
fn test_bit_xor() {
    let a = BigInt::from_u64(0xFF, BigIntWidth::W256);
    let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
    assert_eq!(
        a.bit_xor(&b).unwrap(),
        BigInt::from_u64(0xF0, BigIntWidth::W256)
    );
}

#[test]
fn test_bit_not() {
    let a = BigInt::zero(BigIntWidth::W256);
    let not_a = a.bit_not();
    assert!(not_a.limbs().iter().all(|&l| l == u64::MAX));
}

#[test]
fn test_shl() {
    let a = BigInt::from_u64(1, BigIntWidth::W256);
    let b = a.shl(8).unwrap();
    assert_eq!(b, BigInt::from_u64(256, BigIntWidth::W256));
}

#[test]
fn test_shl_overflow() {
    let a = BigInt::from_u64(1, BigIntWidth::W256);
    // Shift 1 left by 256 should overflow
    assert_eq!(a.shl(256), Err(BigIntError::Overflow));
}

#[test]
fn test_shr() {
    let a = BigInt::from_u64(256, BigIntWidth::W256);
    let b = a.shr(8);
    assert_eq!(b, BigInt::from_u64(1, BigIntWidth::W256));
}

#[test]
fn test_shr_large() {
    let a = BigInt::from_u64(42, BigIntWidth::W256);
    let b = a.shr(256);
    assert!(b.is_zero());
}

// --- Comparison ---

#[test]
fn test_comparison() {
    let a = BigInt::from_u64(10, BigIntWidth::W256);
    let b = BigInt::from_u64(20, BigIntWidth::W256);
    assert!(a < b);
    assert!(b > a);
    assert!(a <= a);
    assert!(a >= a);
}

// --- Width mismatch ---

#[test]
fn test_width_mismatch() {
    let a = BigInt::from_u64(1, BigIntWidth::W256);
    let b = BigInt::from_u64(1, BigIntWidth::W512);
    assert_eq!(a.add(&b), Err(BigIntError::WidthMismatch));
}

// --- Roundtrips ---

#[test]
fn test_hex_roundtrip() {
    let hex = "deadbeef12345678";
    let b = BigInt::from_hex_str(hex, BigIntWidth::W256).unwrap();
    assert_eq!(b.to_hex_string(), hex);
}

#[test]
fn test_decimal_roundtrip() {
    let dec = "123456789012345678901234567890";
    let b = BigInt::from_decimal_str(dec, BigIntWidth::W256).unwrap();
    assert_eq!(b.to_decimal_string(), dec);
}

#[test]
fn test_bits_roundtrip() {
    let b = BigInt::from_u64(42, BigIntWidth::W256);
    let bits = b.to_bits();
    let recovered = BigInt::from_bits(&bits, BigIntWidth::W256).unwrap();
    assert_eq!(b, recovered);
}

// --- Display ---

#[test]
fn test_display_256() {
    let b = BigInt::from_u64(255, BigIntWidth::W256);
    assert_eq!(format!("{}", b), "BigInt256(0xff)");
}

#[test]
fn test_display_512() {
    let b = BigInt::from_u64(255, BigIntWidth::W512);
    assert_eq!(format!("{}", b), "BigInt512(0xff)");
}

// --- 512-bit tests ---

#[test]
fn test_512_add() {
    let a = BigInt::from_u64(100, BigIntWidth::W512);
    let b = BigInt::from_u64(200, BigIntWidth::W512);
    assert_eq!(a.add(&b).unwrap(), BigInt::from_u64(300, BigIntWidth::W512));
}

#[test]
fn test_512_mul() {
    let a = BigInt::from_u64(1000, BigIntWidth::W512);
    let b = BigInt::from_u64(2000, BigIntWidth::W512);
    assert_eq!(
        a.mul(&b).unwrap(),
        BigInt::from_u64(2_000_000, BigIntWidth::W512)
    );
}

#[test]
fn test_shl_cross_limb() {
    let a = BigInt::from_u64(1, BigIntWidth::W256);
    let b = a.shl(64).unwrap();
    assert_eq!(b.limbs()[0], 0);
    assert_eq!(b.limbs()[1], 1);
}

#[test]
fn test_shr_cross_limb() {
    let mut limbs = vec![0u64; 4];
    limbs[1] = 1; // 2^64
    let a = BigInt::from_limbs(limbs, BigIntWidth::W256).unwrap();
    let b = a.shr(64);
    assert_eq!(b, BigInt::from_u64(1, BigIntWidth::W256));
}
