// ---------------------------------------------------------------------------
// 256-bit integer helpers (4 × u64 limbs, little-endian)
// ---------------------------------------------------------------------------

/// Right-shift a 4-limb integer by `shift` bits.
#[allow(clippy::needless_range_loop)]
pub(super) fn shift_right_limbs(limbs: [u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..4 {
        let src = i + word_shift;
        if src < 4 {
            result[i] = limbs[src] >> bit_shift;
            if bit_shift > 0 && src + 1 < 4 {
                result[i] |= limbs[src + 1] << (64 - bit_shift);
            }
        }
    }
    result
}

/// Left-shift a 4-limb integer by `shift` bits.
#[allow(clippy::needless_range_loop)]
pub(super) fn shift_left_limbs(limbs: [u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..4 {
        if i >= word_shift {
            let src = i - word_shift;
            result[i] = limbs[src] << bit_shift;
            if bit_shift > 0 && src > 0 {
                result[i] |= limbs[src - 1] >> (64 - bit_shift);
            }
        }
    }
    result
}

/// Create a bitmask with `num_bits` set bits (as 4 limbs).
pub(super) fn bit_mask_limbs(num_bits: u32) -> [u64; 4] {
    let mut mask = [0u64; 4];
    for i in 0..4 {
        let bits_in_limb = num_bits.saturating_sub(i as u32 * 64).min(64);
        if bits_in_limb == 64 {
            mask[i as usize] = u64::MAX;
        } else if bits_in_limb > 0 {
            mask[i as usize] = (1u64 << bits_in_limb) - 1;
        }
    }
    mask
}
