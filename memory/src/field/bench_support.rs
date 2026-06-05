use crate::limb_ops::sbb;

use super::arithmetic::{
    gte, montgomery_mul, montgomery_reduce, mul_wide, subtract_modulus_if_needed, MODULUS, R2,
};
use super::{Bn254Fr, FieldElement};

#[inline]
pub fn bn254_from_u64(value: u64) -> [u64; 4] {
    FieldElement::<Bn254Fr>::from_u64(value).into_repr()
}

#[inline]
pub fn bn254_modulus() -> [u64; 4] {
    MODULUS
}

#[inline]
pub fn bn254_from_canonical(limbs: [u64; 4]) -> [u64; 4] {
    montgomery_mul(&limbs, &R2)
}

#[inline]
pub fn bn254_montgomery_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    montgomery_mul(a, b)
}

#[inline]
pub fn bn254_mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    mul_wide(a, b)
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn bn254_mul_wide_bmi2_adx(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 8]> {
    if std::arch::is_x86_feature_detected!("bmi2") && std::arch::is_x86_feature_detected!("adx") {
        // SAFETY: Runtime detection above proves both target features
        // before entering the feature-specialized candidate.
        Some(unsafe { bn254_mul_wide_bmi2_adx_unchecked(a, b) })
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2,adx")]
/// Benchmark-only BMI2/ADX wide multiplication candidate.
///
/// # Safety
///
/// The caller must ensure the current CPU supports both BMI2 and ADX.
pub unsafe fn bn254_mul_wide_bmi2_adx_unchecked(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, hi) = mac_bmi2_adx(a[i], b[j], result[i + j], carry);
            result[i + j] = lo;
            carry = hi;
        }
        result[i + 4] = carry;
    }
    result
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn bn254_mul_wide_bmi2_adx(_a: &[u64; 4], _b: &[u64; 4]) -> Option<[u64; 8]> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
/// Benchmark-only BMI2/ADX wide multiplication candidate.
///
/// # Safety
///
/// This function is unreachable on non-x86_64 targets and must not be called.
pub unsafe fn bn254_mul_wide_bmi2_adx_unchecked(_a: &[u64; 4], _b: &[u64; 4]) -> [u64; 8] {
    unreachable!("BMI2/ADX wide multiplication requires x86_64")
}

#[inline]
pub fn bn254_montgomery_reduce(t: &[u64; 8]) -> [u64; 4] {
    montgomery_reduce(t)
}

#[inline]
pub fn bn254_final_reduce_ct(mut limbs: [u64; 4]) -> [u64; 4] {
    subtract_modulus_if_needed(&mut limbs);
    limbs
}

#[inline]
pub fn bn254_final_reduce_branchy(mut limbs: [u64; 4]) -> [u64; 4] {
    if gte(&limbs, &MODULUS) {
        let (r0, borrow) = sbb(limbs[0], MODULUS[0], 0);
        let (r1, borrow) = sbb(limbs[1], MODULUS[1], borrow);
        let (r2, borrow) = sbb(limbs[2], MODULUS[2], borrow);
        let (r3, _) = sbb(limbs[3], MODULUS[3], borrow);
        limbs = [r0, r1, r2, r3];
    }
    limbs
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2,adx")]
fn mac_bmi2_adx(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    use std::arch::x86_64::{_addcarryx_u64, _mulx_u64};

    let mut hi = 0u64;
    let lo = _mulx_u64(a, b, &mut hi);

    let mut sum = 0u64;
    let carry1 = unsafe { _addcarryx_u64(0, lo, c, &mut sum) };
    let mut sum2 = 0u64;
    let carry2 = unsafe { _addcarryx_u64(0, sum, carry, &mut sum2) };

    (sum2, hi + carry1 as u64 + carry2 as u64)
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{
        bn254_final_reduce_branchy, bn254_final_reduce_ct, bn254_mul_wide, bn254_mul_wide_bmi2_adx,
    };
    use crate::field::arithmetic::MODULUS;

    #[test]
    fn bmi2_adx_mul_wide_matches_scalar_when_available() {
        let cases = [
            ([0, 0, 0, 0], [0, 0, 0, 0]),
            ([1, 0, 0, 0], [2, 0, 0, 0]),
            ([u64::MAX, 0, 0, 0], [u64::MAX, 0, 0, 0]),
            (
                [
                    0xffff_ffff_ffff_ffff,
                    0x0123_4567_89ab_cdef,
                    0xfedc_ba98_7654_3210,
                    0x0fff_ffff_ffff_ffff,
                ],
                [
                    0xfeed_face_cafe_beef,
                    0x1111_2222_3333_4444,
                    0x5555_6666_7777_8888,
                    0x000f_ffff_ffff_ffff,
                ],
            ),
        ];

        for (a, b) in cases {
            if let Some(got) = bn254_mul_wide_bmi2_adx(&a, &b) {
                assert_eq!(got, bn254_mul_wide(&a, &b));
            }
        }
    }

    #[test]
    fn branchy_final_reduce_matches_ct() {
        let cases = [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            MODULUS,
            [
                MODULUS[0].wrapping_add(1),
                MODULUS[1],
                MODULUS[2],
                MODULUS[3],
            ],
            [u64::MAX, u64::MAX, u64::MAX, MODULUS[3]],
        ];

        for limbs in cases {
            assert_eq!(
                bn254_final_reduce_branchy(limbs),
                bn254_final_reduce_ct(limbs)
            );
        }
    }
}
