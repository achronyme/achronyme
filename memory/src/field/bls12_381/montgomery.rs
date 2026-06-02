use super::super::arithmetic::mul_wide;
use super::constants::{INV, MODULUS};
use crate::limb_ops::{adc, mac, sbb};

/// Conditionally subtract BLS12-381 modulus if value >= MODULUS (constant-time).
#[inline]
pub(super) fn subtract_modulus_if_needed(limbs: &mut [u64; 4]) {
    let (r0, borrow) = sbb(limbs[0], MODULUS[0], 0);
    let (r1, borrow) = sbb(limbs[1], MODULUS[1], borrow);
    let (r2, borrow) = sbb(limbs[2], MODULUS[2], borrow);
    let (r3, borrow) = sbb(limbs[3], MODULUS[3], borrow);
    let mask = 0u64.wrapping_sub(borrow);
    limbs[0] = (limbs[0] & mask) | (r0 & !mask);
    limbs[1] = (limbs[1] & mask) | (r1 & !mask);
    limbs[2] = (limbs[2] & mask) | (r2 & !mask);
    limbs[3] = (limbs[3] & mask) | (r3 & !mask);
}

/// Montgomery reduction for BLS12-381: T . R^-1 mod p (CIOS).
pub(super) fn montgomery_reduce(t: &[u64; 8]) -> [u64; 4] {
    let (r0, mut r1, mut r2, mut r3) = (t[0], t[1], t[2], t[3]);
    let (mut r4, mut r5, mut r6, mut r7) = (t[4], t[5], t[6], t[7]);

    // Iteration 0
    let k = r0.wrapping_mul(INV);
    let (_, mut carry) = mac(k, MODULUS[0], r0, 0);
    (r1, carry) = mac(k, MODULUS[1], r1, carry);
    (r2, carry) = mac(k, MODULUS[2], r2, carry);
    (r3, carry) = mac(k, MODULUS[3], r3, carry);
    let mut carry2;
    (r4, carry2) = adc(r4, carry, 0);

    // Iteration 1
    let k = r1.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r1, 0);
    (r2, carry) = mac(k, MODULUS[1], r2, carry);
    (r3, carry) = mac(k, MODULUS[2], r3, carry);
    (r4, carry) = mac(k, MODULUS[3], r4, carry);
    (r5, carry2) = adc(r5, carry, carry2);

    // Iteration 2
    let k = r2.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r2, 0);
    (r3, carry) = mac(k, MODULUS[1], r3, carry);
    (r4, carry) = mac(k, MODULUS[2], r4, carry);
    (r5, carry) = mac(k, MODULUS[3], r5, carry);
    (r6, carry2) = adc(r6, carry, carry2);

    // Iteration 3
    let k = r3.wrapping_mul(INV);
    (_, carry) = mac(k, MODULUS[0], r3, 0);
    (r4, carry) = mac(k, MODULUS[1], r4, carry);
    (r5, carry) = mac(k, MODULUS[2], r5, carry);
    (r6, carry) = mac(k, MODULUS[3], r6, carry);
    (r7, _) = adc(r7, carry, carry2);

    let mut result = [r4, r5, r6, r7];
    subtract_modulus_if_needed(&mut result);
    result
}

/// Montgomery multiplication for BLS12-381: a * b * R^{-1} mod p.
#[inline]
pub(super) fn montgomery_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    montgomery_reduce(&mul_wide(a, b))
}

/// Modular addition for BLS12-381: (a + b) mod p.
#[inline]
pub(super) fn montgomery_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, carry) = adc(a[0], b[0], 0);
    let (r1, carry) = adc(a[1], b[1], carry);
    let (r2, carry) = adc(a[2], b[2], carry);
    let (r3, _) = adc(a[3], b[3], carry);
    let mut result = [r0, r1, r2, r3];
    subtract_modulus_if_needed(&mut result);
    result
}

/// Modular subtraction for BLS12-381: (a - b) mod p (constant-time).
#[inline]
pub(super) fn montgomery_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow) = sbb(a[0], b[0], 0);
    let (r1, borrow) = sbb(a[1], b[1], borrow);
    let (r2, borrow) = sbb(a[2], b[2], borrow);
    let (r3, borrow) = sbb(a[3], b[3], borrow);
    let mask = 0u64.wrapping_sub(borrow);
    let (r0, carry) = adc(r0, MODULUS[0] & mask, 0);
    let (r1, carry) = adc(r1, MODULUS[1] & mask, carry);
    let (r2, carry) = adc(r2, MODULUS[2] & mask, carry);
    let (r3, _) = adc(r3, MODULUS[3] & mask, carry);
    [r0, r1, r2, r3]
}

/// Modular negation for BLS12-381: (-a) mod p (constant-time).
#[inline]
pub(super) fn montgomery_neg(a: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow) = sbb(MODULUS[0], a[0], 0);
    let (r1, borrow) = sbb(MODULUS[1], a[1], borrow);
    let (r2, borrow) = sbb(MODULUS[2], a[2], borrow);
    let (r3, _) = sbb(MODULUS[3], a[3], borrow);
    let is_nonzero = a[0] | a[1] | a[2] | a[3];
    let mask = (is_nonzero | is_nonzero.wrapping_neg()) >> 63;
    let mask = 0u64.wrapping_sub(mask);
    [r0 & mask, r1 & mask, r2 & mask, r3 & mask]
}
