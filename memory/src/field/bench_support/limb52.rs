use crate::field::arithmetic::montgomery_reduce;

use super::LIMB52_MASK;

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
    let mut acc = [0u128; 9];
    for i in 0..5 {
        for j in 0..5 {
            acc[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }
    normalize_product_coefficients(&acc)
}

#[inline]
pub fn bn254_montgomery_mul_5x52_hybrid(a: &[u64; 5], b: &[u64; 5]) -> [u64; 4] {
    let wide = bn254_mul_wide_5x52(a, b);
    montgomery_reduce(&limbs52_wide_to_limbs64(&wide))
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn bn254_mul_wide_5x52_ifma(a: &[u64; 5], b: &[u64; 5]) -> Option<[u64; 10]> {
    if std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
    {
        // SAFETY: Runtime detection above proves AVX-512F/IFMA support.
        Some(unsafe { bn254_mul_wide_5x52_ifma_unchecked(a, b) })
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
/// Benchmark-only AVX-512 IFMA 5x52 wide product candidate.
///
/// This forms the nine product diagonals with `vpmadd52*`, then performs the
/// horizontal diagonal sums and carry normalization in scalar code. It is a
/// diagnostic integration shape, not a production field kernel.
///
/// # Safety
///
/// The caller must ensure AVX-512F and AVX-512IFMA are available, and inputs
/// must be reduced to 52-bit limbs.
pub unsafe fn bn254_mul_wide_5x52_ifma_unchecked(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    let mut acc = [0u128; 9];
    for (diagonal, slot) in acc.iter_mut().enumerate() {
        *slot = ifma_diagonal_sum(a, b, diagonal);
    }
    normalize_product_coefficients(&acc)
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn bn254_montgomery_mul_5x52_ifma_hybrid(a: &[u64; 5], b: &[u64; 5]) -> Option<[u64; 4]> {
    if std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
    {
        // SAFETY: Runtime detection above proves AVX-512F/IFMA support.
        Some(unsafe { bn254_montgomery_mul_5x52_ifma_hybrid_unchecked(a, b) })
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
/// Benchmark-only hybrid Montgomery candidate.
///
/// The product is formed in 5x52 IFMA shape, converted back to 4x64 wide
/// limbs, then reduced by the existing Montgomery reducer.
///
/// # Safety
///
/// The caller must ensure AVX-512F and AVX-512IFMA are available, and inputs
/// must be reduced to 52-bit limbs.
pub unsafe fn bn254_montgomery_mul_5x52_ifma_hybrid_unchecked(
    a: &[u64; 5],
    b: &[u64; 5],
) -> [u64; 4] {
    let wide = bn254_mul_wide_5x52_ifma_unchecked(a, b);
    montgomery_reduce(&limbs52_wide_to_limbs64(&wide))
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn bn254_mul_wide_5x52_ifma(_a: &[u64; 5], _b: &[u64; 5]) -> Option<[u64; 10]> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn bn254_montgomery_mul_5x52_ifma_hybrid(_a: &[u64; 5], _b: &[u64; 5]) -> Option<[u64; 4]> {
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
fn ifma_diagonal_sum(a: &[u64; 5], b: &[u64; 5], diagonal: usize) -> u128 {
    use std::arch::x86_64::{
        __m512i, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_set_epi64,
        _mm512_setzero_si512, _mm512_storeu_si512,
    };

    let mut lanes_a = [0u64; 8];
    let mut lanes_b = [0u64; 8];
    let start = diagonal.saturating_sub(4);
    let end = diagonal.min(4);
    let mut lane_count = 0usize;

    for (i, a_limb) in a.iter().enumerate().take(end + 1).skip(start) {
        let j = diagonal - i;
        lanes_a[lane_count] = *a_limb;
        lanes_b[lane_count] = b[j];
        lane_count += 1;
    }

    let a_vec = _mm512_set_epi64(
        lanes_a[7] as i64,
        lanes_a[6] as i64,
        lanes_a[5] as i64,
        lanes_a[4] as i64,
        lanes_a[3] as i64,
        lanes_a[2] as i64,
        lanes_a[1] as i64,
        lanes_a[0] as i64,
    );
    let b_vec = _mm512_set_epi64(
        lanes_b[7] as i64,
        lanes_b[6] as i64,
        lanes_b[5] as i64,
        lanes_b[4] as i64,
        lanes_b[3] as i64,
        lanes_b[2] as i64,
        lanes_b[1] as i64,
        lanes_b[0] as i64,
    );
    let zero = _mm512_setzero_si512();
    let lo_vec = _mm512_madd52lo_epu64(zero, a_vec, b_vec);
    let hi_vec = _mm512_madd52hi_epu64(zero, a_vec, b_vec);

    let mut lo = [0u64; 8];
    let mut hi = [0u64; 8];
    unsafe {
        _mm512_storeu_si512(lo.as_mut_ptr().cast::<__m512i>(), lo_vec);
        _mm512_storeu_si512(hi.as_mut_ptr().cast::<__m512i>(), hi_vec);
    }

    let lo_sum: u128 = lo[..lane_count].iter().map(|value| *value as u128).sum();
    let hi_sum: u128 = hi[..lane_count].iter().map(|value| *value as u128).sum();
    lo_sum + (hi_sum << 52)
}

#[inline]
fn normalize_product_coefficients(acc: &[u128; 9]) -> [u64; 10] {
    let mut out = [0u64; 10];
    let mut carry = 0u128;
    for idx in 0..9 {
        let value = acc[idx] + carry;
        out[idx] = (value as u64) & LIMB52_MASK;
        carry = value >> 52;
    }
    out[9] = carry as u64;
    debug_assert!(carry <= LIMB52_MASK as u128);
    out
}

fn limbs52_wide_to_limbs64(limbs: &[u64; 10]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (out_idx, slot) in out.iter_mut().enumerate() {
        *slot = read_bits_52(limbs, out_idx * 64, 64);
    }
    out
}

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::{
        bn254_limbs4_to_limbs52, bn254_limbs52_to_limbs4, bn254_montgomery_mul_5x52_hybrid,
        bn254_mul_wide_5x52, high_bits_after_512, limbs52_wide_to_limbs64,
    };
    use crate::field::arithmetic::mul_wide;
    use crate::field::bench_support::{bn254_montgomery_mul, LIMB52_MASK};

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
            assert_eq!(limbs52_wide_to_limbs64(&product52), mul_wide(&a, &b));
            assert_eq!(high_bits_after_512(&product52), 0);
        }
    }

    #[test]
    fn montgomery_mul_5x52_hybrid_matches_limbs4() {
        for (a, b) in deterministic_limbs4_pairs() {
            assert_eq!(
                bn254_montgomery_mul_5x52_hybrid(
                    &bn254_limbs4_to_limbs52(&a),
                    &bn254_limbs4_to_limbs52(&b)
                ),
                bn254_montgomery_mul(&a, &b)
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma52_mul_wide_5x52_matches_scalar_when_available() {
        use super::bn254_mul_wide_5x52_ifma;

        for (a, b) in deterministic_limbs4_pairs() {
            let a52 = bn254_limbs4_to_limbs52(&a);
            let b52 = bn254_limbs4_to_limbs52(&b);
            if let Some(got) = bn254_mul_wide_5x52_ifma(&a52, &b52) {
                assert_eq!(got, bn254_mul_wide_5x52(&a52, &b52));
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma52_montgomery_hybrid_matches_limbs4_when_available() {
        use super::bn254_montgomery_mul_5x52_ifma_hybrid;

        for (a, b) in deterministic_limbs4_pairs() {
            if let Some(got) = bn254_montgomery_mul_5x52_ifma_hybrid(
                &bn254_limbs4_to_limbs52(&a),
                &bn254_limbs4_to_limbs52(&b),
            ) {
                assert_eq!(got, bn254_montgomery_mul(&a, &b));
            }
        }
    }

    fn deterministic_limbs4_pairs() -> impl Iterator<Item = ([u64; 4], [u64; 4])> {
        let mut x = 0xb5ad_4ece_da1c_600du64;
        (0..4096).map(move |_| {
            let mut next = || {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                x.wrapping_mul(0x2545_f491_4f6c_dd1d)
            };
            (
                [next(), next(), next(), next()],
                [next(), next(), next(), next()],
            )
        })
    }
}
