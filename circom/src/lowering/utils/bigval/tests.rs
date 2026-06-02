use super::*;
use std::cmp::Ordering;

#[test]
fn basic_add_sub() {
    let a = BigVal::from_i64(10);
    let b = BigVal::from_i64(20);
    assert_eq!(a.add(b).to_i64(), Some(30));
    assert_eq!(b.sub(a).to_i64(), Some(10));
    assert_eq!(a.sub(b).to_i64(), Some(-10));
}

#[test]
fn neg_and_abs() {
    let a = BigVal::from_i64(-5);
    assert!(a.is_negative());
    assert_eq!(a.neg().to_i64(), Some(5));
    assert_eq!(a.abs().to_i64(), Some(5));
}

#[test]
fn mul_basic() {
    let a = BigVal::from_i64(12345);
    let b = BigVal::from_i64(67890);
    assert_eq!(a.mul(b).to_i64(), Some(12345 * 67890));
}

#[test]
fn mul_signed() {
    let a = BigVal::from_i64(-3);
    let b = BigVal::from_i64(7);
    assert_eq!(a.mul(b).to_i64(), Some(-21));
}

#[test]
fn shift_left_128() {
    // The critical test case: 1 << 128
    let one = BigVal::ONE;
    let shifted = one.shl(128);
    assert_eq!(shifted.0, [0, 0, 1, 0]);
    assert!(!shifted.is_negative());
    assert!(shifted.to_u64().is_none()); // doesn't fit in u64

    // (1 << 128) - 1 = 2^128 - 1
    let result = shifted.sub(BigVal::ONE);
    assert_eq!(result.0, [u64::MAX, u64::MAX, 0, 0]);
}

#[test]
fn shift_right_extracts_bits() {
    // CompConstant: (ct >> i) & 1
    let val = BigVal([0xFF00, 0, 0, 0]);
    assert_eq!(val.shr(8).bitand(BigVal::ONE).to_i64(), Some(1));
    assert_eq!(val.shr(7).bitand(BigVal::ONE).to_i64(), Some(0));
}

#[test]
fn shift_right_large() {
    let val = BigVal([0, 0, 1, 0]); // 2^128
    let shifted = val.shr(64);
    assert_eq!(shifted.0, [0, 1, 0, 0]); // 2^64
}

#[test]
fn signed_comparison() {
    let pos = BigVal::from_i64(5);
    let neg = BigVal::from_i64(-1);
    let zero = BigVal::ZERO;

    assert_eq!(pos.cmp_signed(neg), Ordering::Greater);
    assert_eq!(neg.cmp_signed(pos), Ordering::Less);
    assert_eq!(neg.cmp_signed(zero), Ordering::Less);
    assert_eq!(zero.cmp_signed(neg), Ordering::Greater);
}

#[test]
fn div_and_rem() {
    let a = BigVal::from_i64(17);
    let b = BigVal::from_i64(5);
    assert_eq!(a.div(b), Some(BigVal::from_i64(3)));
    assert_eq!(a.rem(b), Some(BigVal::from_i64(2)));

    let c = BigVal::from_i64(-17);
    assert_eq!(c.div(b), Some(BigVal::from_i64(-3)));
    assert_eq!(c.rem(b), Some(BigVal::from_i64(-2)));
}

#[test]
fn div_by_zero() {
    assert_eq!(BigVal::ONE.div(BigVal::ZERO), None);
}

#[test]
fn pow_basic() {
    let base = BigVal::from_i64(2);
    assert_eq!(base.pow(10).to_i64(), Some(1024));
    assert_eq!(BigVal::from_i64(3).pow(0).to_i64(), Some(1));
}

#[test]
fn bitwise_ops() {
    let a = BigVal::from_u64(0xFF);
    let b = BigVal::from_u64(0x0F);
    assert_eq!(a.bitand(b).to_u64(), Some(0x0F));
    assert_eq!(a.bitor(b).to_u64(), Some(0xFF));
    assert_eq!(a.bitxor(b).to_u64(), Some(0xF0));
}

#[test]
fn field_const_roundtrip() {
    let val = BigVal::ONE.shl(128).sub(BigVal::ONE); // 2^128 - 1
    let fc = val.to_field_const();
    let back = BigVal::from_field_const(fc);
    assert_eq!(val, back);
}

#[test]
fn to_i64_boundary() {
    assert_eq!(BigVal::from_i64(i64::MAX).to_i64(), Some(i64::MAX));
    assert_eq!(BigVal::from_i64(i64::MIN).to_i64(), Some(i64::MIN));
    assert_eq!(BigVal::from_i64(0).to_i64(), Some(0));
    assert_eq!(BigVal::from_i64(-1).to_i64(), Some(-1));
}

#[test]
fn loop_variable_goes_negative() {
    // Simulate: for (var i = 2; i >= 0; i--)
    let mut i = BigVal::from_i64(2);
    let zero = BigVal::ZERO;
    let mut iterations = 0;
    while i.cmp_signed(zero) != Ordering::Less {
        iterations += 1;
        i = i.sub(BigVal::ONE);
    }
    assert_eq!(iterations, 3); // i=2, i=1, i=0
    assert_eq!(i.to_i64(), Some(-1));
}

#[test]
fn compconstant_simulation() {
    // Simulate the CompConstant var computation:
    // var b = (1 << 128) - 1;
    // var a = 1; var e = 1;
    // for i in 0..127: b = b - e; a = a + e; e = e * 2;
    let mut b = BigVal::ONE.shl(128).sub(BigVal::ONE);
    let mut a = BigVal::ONE;
    let mut e = BigVal::ONE;

    let initial_b = b;
    assert_eq!(initial_b.0, [u64::MAX, u64::MAX, 0, 0]); // 2^128 - 1

    for _ in 0..127 {
        b = b.sub(e);
        a = a.add(e);
        e = e.mul(BigVal::from_i64(2));
    }

    // After 127 iterations: e = 2^127
    // sum of e values = 1+2+4+...+2^126 = 2^127 - 1
    // b = (2^128-1) - (2^127-1) = 2^127
    // a = 1 + (2^127-1) = 2^127
    assert_eq!(e.0, [0, 1 << 63, 0, 0]); // 2^127
    assert_eq!(b.0, [0, 1 << 63, 0, 0]); // 2^127
    assert_eq!(a.0, [0, 1 << 63, 0, 0]); // 2^127
}
