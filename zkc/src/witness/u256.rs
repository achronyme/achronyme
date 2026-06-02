use memory::{FieldBackend, FieldElement};

/// Integer division and modulo on field elements interpreted as unsigned integers.
///
/// Returns `(q, r)` where `a = b * q + r` and `0 <= r < b`.
/// Both `a` and `b` are given as 4-limb canonical representations.
pub fn int_divmod_field_pub<F: FieldBackend>(
    a_limbs: &[u64; 4],
    b_limbs: &[u64; 4],
) -> (FieldElement<F>, FieldElement<F>) {
    // Check if both values fit in a single u64 (common case)
    let a_small = a_limbs[1] == 0 && a_limbs[2] == 0 && a_limbs[3] == 0;
    let b_small = b_limbs[1] == 0 && b_limbs[2] == 0 && b_limbs[3] == 0;

    if a_small && b_small {
        let a = a_limbs[0];
        let b = b_limbs[0];
        if b == 0 {
            return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
        }
        let q = a / b;
        let r = a % b;
        return (
            FieldElement::<F>::from_u64(q),
            FieldElement::<F>::from_u64(r),
        );
    }

    // Multi-limb: convert to BigUint-style division
    // For now, use a simple shift-and-subtract algorithm on 256-bit values
    let a_val = limbs_to_u256(a_limbs);
    let b_val = limbs_to_u256(b_limbs);
    if b_val == [0u64; 4] {
        return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
    }
    let (q_val, r_val) = divmod_u256(&a_val, &b_val);
    (u256_to_field::<F>(&q_val), u256_to_field::<F>(&r_val))
}

fn limbs_to_u256(limbs: &[u64; 4]) -> [u64; 4] {
    *limbs
}

fn u256_to_field<F: FieldBackend>(limbs: &[u64; 4]) -> FieldElement<F> {
    // Reconstruct: limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192
    let mut result = FieldElement::<F>::from_u64(limbs[0]);
    if limbs[1] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        result = result.add(&FieldElement::<F>::from_u64(limbs[1]).mul(&shift64));
    }
    if limbs[2] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        let shift128 = shift64.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[2]).mul(&shift128));
    }
    if limbs[3] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        let shift128 = shift64.mul(&shift64);
        let shift192 = shift128.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[3]).mul(&shift192));
    }
    result
}

/// Simple shift-and-subtract 256-bit unsigned division.
fn divmod_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    if cmp_u256(a, b) == std::cmp::Ordering::Less {
        return ([0; 4], *a);
    }

    let mut remainder = *a;
    let mut quotient = [0u64; 4];

    // Find highest set bit of b
    let b_bits = 256 - leading_zeros_u256(b);
    let a_bits = 256 - leading_zeros_u256(a);

    if b_bits == 0 {
        return ([0; 4], [0; 4]); // division by zero
    }

    let shift = a_bits - b_bits;
    let mut shifted_b = shl_u256(b, shift);

    for i in (0..=shift).rev() {
        if cmp_u256(&remainder, &shifted_b) != std::cmp::Ordering::Less {
            remainder = sub_u256(&remainder, &shifted_b);
            let word = i / 64;
            let bit = i % 64;
            quotient[word] |= 1u64 << bit;
        }
        shifted_b = shr_u256(&shifted_b, 1);
    }

    (quotient, remainder)
}

fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

fn leading_zeros_u256(a: &[u64; 4]) -> usize {
    for i in (0..4).rev() {
        if a[i] != 0 {
            return (3 - i) * 64 + a[i].leading_zeros() as usize;
        }
    }
    256
}

fn shl_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in word_shift..4 {
        result[i] = a[i - word_shift] << bit_shift;
        if bit_shift > 0 && i > word_shift {
            result[i] |= a[i - word_shift - 1] >> (64 - bit_shift);
        }
    }
    result
}

fn shr_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..(4 - word_shift) {
        result[i] = a[i + word_shift] >> bit_shift;
        if bit_shift > 0 && i + word_shift + 1 < 4 {
            result[i] |= a[i + word_shift + 1] << (64 - bit_shift);
        }
    }
    result
}

fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result
}
