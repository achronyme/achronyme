use crate::limb_ops::sbb;

use super::arithmetic::{
    gte, montgomery_mul, montgomery_reduce, mul_wide, subtract_modulus_if_needed, MODULUS, R2,
};
use super::{Bn254Fr, FieldElement};

const LIMB52_MASK: u64 = (1u64 << 52) - 1;

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

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn bn254_ifma52_madd8(a: &[u64; 8], b: &[u64; 8]) -> Option<([u64; 8], [u64; 8])> {
    if std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
    {
        // SAFETY: Runtime detection above proves both target features
        // before entering the feature-specialized candidate.
        Some(unsafe { bn254_ifma52_madd8_unchecked(a, b) })
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
/// Benchmark-only AVX-512 IFMA 52-bit lane multiply-add primitive.
///
/// Returns the low and high 52-bit halves of eight independent `a[i] * b[i]`
/// products, matching the primitive shape needed by a future 5x52 field
/// kernel. This is not a complete Montgomery multiplication.
///
/// # Safety
///
/// The caller must ensure the current CPU supports AVX-512F and AVX-512IFMA,
/// and inputs must be reduced to 52-bit limbs.
pub unsafe fn bn254_ifma52_madd8_unchecked(a: &[u64; 8], b: &[u64; 8]) -> ([u64; 8], [u64; 8]) {
    use std::arch::x86_64::{
        __m512i, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_set_epi64,
        _mm512_setzero_si512, _mm512_storeu_si512,
    };

    let lanes_a = _mm512_set_epi64(
        a[7] as i64,
        a[6] as i64,
        a[5] as i64,
        a[4] as i64,
        a[3] as i64,
        a[2] as i64,
        a[1] as i64,
        a[0] as i64,
    );
    let lanes_b = _mm512_set_epi64(
        b[7] as i64,
        b[6] as i64,
        b[5] as i64,
        b[4] as i64,
        b[3] as i64,
        b[2] as i64,
        b[1] as i64,
        b[0] as i64,
    );
    let zero = _mm512_setzero_si512();
    let lo = _mm512_madd52lo_epu64(zero, lanes_a, lanes_b);
    let hi = _mm512_madd52hi_epu64(zero, lanes_a, lanes_b);

    let mut lo_out = [0u64; 8];
    let mut hi_out = [0u64; 8];
    _mm512_storeu_si512(lo_out.as_mut_ptr().cast::<__m512i>(), lo);
    _mm512_storeu_si512(hi_out.as_mut_ptr().cast::<__m512i>(), hi);
    (lo_out, hi_out)
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

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn bn254_ifma52_madd8(_a: &[u64; 8], _b: &[u64; 8]) -> Option<([u64; 8], [u64; 8])> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
/// Benchmark-only AVX-512 IFMA 52-bit lane multiply-add primitive.
///
/// # Safety
///
/// This function is unreachable on non-x86_64 targets and must not be called.
pub unsafe fn bn254_ifma52_madd8_unchecked(_a: &[u64; 8], _b: &[u64; 8]) -> ([u64; 8], [u64; 8]) {
    unreachable!("AVX-512 IFMA requires x86_64")
}

#[inline]
pub fn bn254_scalar52_madd8(a: &[u64; 8], b: &[u64; 8]) -> ([u64; 8], [u64; 8]) {
    let mut lo = [0u64; 8];
    let mut hi = [0u64; 8];
    for idx in 0..8 {
        let product = (a[idx] as u128) * (b[idx] as u128);
        lo[idx] = (product as u64) & LIMB52_MASK;
        hi[idx] = (product >> 52) as u64;
    }
    (lo, hi)
}

#[inline]
pub fn bn254_limbs4_to_limbs52(limbs: &[u64; 4]) -> [u64; 5] {
    [
        limbs[0] & LIMB52_MASK,
        (limbs[0] >> 52) | ((limbs[1] & ((1u64 << 40) - 1)) << 12),
        (limbs[1] >> 40) | ((limbs[2] & ((1u64 << 28) - 1)) << 24),
        (limbs[2] >> 28) | ((limbs[3] & ((1u64 << 16) - 1)) << 36),
        limbs[3] >> 16,
    ]
}

#[inline]
pub fn bn254_limbs52_to_limbs4(limbs: &[u64; 5]) -> [u64; 4] {
    [
        (limbs[0] & LIMB52_MASK) | ((limbs[1] & ((1u64 << 12) - 1)) << 52),
        (limbs[1] >> 12) | ((limbs[2] & ((1u64 << 24) - 1)) << 40),
        (limbs[2] >> 24) | ((limbs[3] & ((1u64 << 36) - 1)) << 28),
        (limbs[3] >> 36) | (limbs[4] << 16),
    ]
}

#[inline]
pub fn bn254_mul_wide_5x52(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    let mut acc = [0u128; 10];
    for i in 0..5 {
        for j in 0..5 {
            acc[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }

    let mut out = [0u64; 10];
    let mut carry = 0u128;
    for idx in 0..10 {
        let value = acc[idx] + carry;
        out[idx] = (value as u64) & LIMB52_MASK;
        carry = value >> 52;
    }
    debug_assert_eq!(carry, 0);
    out
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
        bn254_final_reduce_branchy, bn254_final_reduce_ct, bn254_ifma52_madd8,
        bn254_limbs4_to_limbs52, bn254_limbs52_to_limbs4, bn254_mul_wide, bn254_mul_wide_5x52,
        bn254_mul_wide_bmi2_adx, bn254_scalar52_madd8, LIMB52_MASK,
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

    #[test]
    fn ifma52_madd8_matches_scalar_when_available() {
        let mut x = 0x517c_c1b7_2722_0a95u64;
        for _ in 0..4096 {
            let mut next = || {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                x.wrapping_mul(0x2545_f491_4f6c_dd1d) & LIMB52_MASK
            };
            let a = [
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
            ];
            let b = [
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
            ];
            if let Some(got) = bn254_ifma52_madd8(&a, &b) {
                assert_eq!(got, bn254_scalar52_madd8(&a, &b));
            }
        }
    }

    #[test]
    fn limb52_roundtrip_matches_limbs4() {
        let cases = [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [u64::MAX, 0, 0, 0],
            [0, u64::MAX, 0, 0],
            [0, 0, u64::MAX, 0],
            [0, 0, 0, u64::MAX],
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX],
            [
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
                0x0bad_f00d_cafe_beef,
                0x1357_9bdf_2468_ace0,
            ],
        ];

        for limbs in cases {
            let limbs52 = bn254_limbs4_to_limbs52(&limbs);
            assert!(limbs52.iter().all(|limb| *limb <= LIMB52_MASK));
            assert_eq!(bn254_limbs52_to_limbs4(&limbs52), limbs);
        }
    }

    #[test]
    fn mul_wide_5x52_matches_limbs4_product() {
        let mut x = 0xa409_3822_299f_31d0u64;
        let mut next = || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };

        for _ in 0..4096 {
            let a = [next(), next(), next(), next()];
            let b = [next(), next(), next(), next()];
            let product52 =
                bn254_mul_wide_5x52(&bn254_limbs4_to_limbs52(&a), &bn254_limbs4_to_limbs52(&b));
            assert_eq!(limbs52_wide_to_limbs64(&product52), bn254_mul_wide(&a, &b));
            assert_eq!(high_bits_after_512(&product52), 0);
        }
    }

    fn limbs52_wide_to_limbs64(limbs: &[u64; 10]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for (out_idx, slot) in out.iter_mut().enumerate() {
            *slot = read_bits_52(limbs, out_idx * 64, 64);
        }
        out
    }

    fn high_bits_after_512(limbs: &[u64; 10]) -> u64 {
        read_bits_52(limbs, 512, 8)
    }

    fn read_bits_52(limbs: &[u64; 10], start: usize, len: usize) -> u64 {
        let mut out = 0u64;
        let mut written = 0usize;
        let mut bit = start;
        while written < len {
            let limb_idx = bit / 52;
            let offset = bit % 52;
            let take = (len - written).min(52 - offset);
            let mask = if take == 64 {
                u64::MAX
            } else {
                (1u64 << take) - 1
            };
            let part = (limbs[limb_idx] >> offset) & mask;
            out |= part << written;
            written += take;
            bit += take;
        }
        out
    }
}
