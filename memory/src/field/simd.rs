#[inline]
pub(crate) fn ct_select_u64x4(a: &[u64; 4], b: &[u64; 4], flag: u64) -> Option<[u64; 4]> {
    #[cfg(target_arch = "x86_64")]
    {
        if x86_64::ct_select_impl() == x86_64::CT_SELECT_AVX2 {
            // SAFETY: The runtime check above guarantees AVX2 support
            // before entering the target-feature function.
            return Some(unsafe { x86_64::ct_select_u64x4_avx2(a, b, flag) });
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use std::sync::atomic::{AtomicU8, Ordering};

    use std::arch::x86_64::{
        __m256i, _mm256_and_si256, _mm256_andnot_si256, _mm256_loadu_si256, _mm256_or_si256,
        _mm256_set1_epi64x, _mm256_storeu_si256,
    };

    const CT_SELECT_UNKNOWN: u8 = 0;
    pub(super) const CT_SELECT_SCALAR: u8 = 1;
    pub(super) const CT_SELECT_AVX2: u8 = 2;

    static CT_SELECT_IMPL: AtomicU8 = AtomicU8::new(CT_SELECT_UNKNOWN);

    #[inline]
    pub(super) fn ct_select_impl() -> u8 {
        let cached = CT_SELECT_IMPL.load(Ordering::Relaxed);
        if cached != CT_SELECT_UNKNOWN {
            return cached;
        }
        let detected = if std::arch::is_x86_feature_detected!("avx2") {
            CT_SELECT_AVX2
        } else {
            CT_SELECT_SCALAR
        };
        CT_SELECT_IMPL.store(detected, Ordering::Relaxed);
        detected
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn ct_select_u64x4_avx2(a: &[u64; 4], b: &[u64; 4], flag: u64) -> [u64; 4] {
        let mask = 0u64.wrapping_sub(flag);
        let mask_v = _mm256_set1_epi64x(mask as i64);
        // SAFETY: `a` and `b` point to four contiguous u64 limbs
        // (32 bytes). Unaligned loads are explicitly allowed here.
        let a_v = unsafe { _mm256_loadu_si256(a.as_ptr().cast::<__m256i>()) };
        let b_v = unsafe { _mm256_loadu_si256(b.as_ptr().cast::<__m256i>()) };
        let selected = _mm256_or_si256(
            _mm256_andnot_si256(mask_v, a_v),
            _mm256_and_si256(mask_v, b_v),
        );
        let mut out = [0u64; 4];
        // SAFETY: `out` points to four contiguous u64 limbs
        // (32 bytes). Unaligned stores are explicitly allowed here.
        unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast::<__m256i>(), selected) };
        out
    }
}

#[cfg(test)]
mod tests {
    use super::ct_select_u64x4;
    use crate::field::arithmetic::montgomery4_ct_select_scalar;

    #[test]
    fn ct_select_simd_matches_scalar_when_available() {
        let a = [0, 1, u64::MAX, 0x0123_4567_89ab_cdef];
        let b = [u64::MAX, 5, 9, 0xfedc_ba98_7654_3210];
        for flag in [0, 1, 2, u64::MAX] {
            if let Some(got) = ct_select_u64x4(&a, &b, flag) {
                assert_eq!(got, montgomery4_ct_select_scalar(&a, &b, flag));
            }
        }
    }
}
