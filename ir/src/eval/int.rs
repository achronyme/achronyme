use memory::{FieldBackend, FieldElement};

pub(super) fn fits_in_bits<F: FieldBackend>(v: &FieldElement<F>, bits: u32) -> bool {
    if bits >= 256 {
        return true;
    }
    let limbs = v.to_canonical();
    // Check each 64-bit limb
    for (i, &limb) in limbs.iter().enumerate() {
        let limb_start = (i as u32) * 64;
        if limb_start >= bits {
            // This entire limb must be zero
            if limb != 0 {
                return false;
            }
        } else {
            let remaining_bits = bits - limb_start;
            if remaining_bits < 64 {
                // Only lower `remaining_bits` bits allowed
                if limb >= (1u64 << remaining_bits) {
                    return false;
                }
            }
            // If remaining_bits >= 64, the whole limb is fine
        }
    }
    true
}

/// Integer division and modulo on field elements (unsigned).
/// Returns `(q, r)` where `a = b * q + r` and `0 <= r < b`.
pub(super) fn int_divmod_field<F: FieldBackend>(
    a: &FieldElement<F>,
    b: &FieldElement<F>,
) -> (FieldElement<F>, FieldElement<F>) {
    let a_limbs = a.to_canonical();
    let b_limbs = b.to_canonical();
    let a_small = a_limbs[1] == 0 && a_limbs[2] == 0 && a_limbs[3] == 0;
    let b_small = b_limbs[1] == 0 && b_limbs[2] == 0 && b_limbs[3] == 0;
    if b_small && b_limbs[0] == 0 {
        return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
    }
    if a_small && b_small {
        let q = a_limbs[0] / b_limbs[0];
        let r = a_limbs[0] % b_limbs[0];
        return (
            FieldElement::<F>::from_u64(q),
            FieldElement::<F>::from_u64(r),
        );
    }
    // Multi-limb: use shift-and-subtract
    let (q, r) = divmod_u256(&a_limbs, &b_limbs);
    (u256_to_field::<F>(&q), u256_to_field::<F>(&r))
}

fn divmod_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let a_bits = 256 - leading_zeros_u256(a);
    let b_bits = 256 - leading_zeros_u256(b);
    if b_bits == 0 || cmp_u256(a, b) == std::cmp::Ordering::Less {
        return ([0; 4], *a);
    }
    let shift = a_bits - b_bits;
    let mut rem = *a;
    let mut quot = [0u64; 4];
    let mut shifted = shl_u256(b, shift);
    for i in (0..=shift).rev() {
        if cmp_u256(&rem, &shifted) != std::cmp::Ordering::Less {
            rem = sub_u256(&rem, &shifted);
            quot[i / 64] |= 1u64 << (i % 64);
        }
        shifted = shr_u256(&shifted, 1);
    }
    (quot, rem)
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
    let (ws, bs) = (shift / 64, shift % 64);
    let mut r = [0u64; 4];
    for i in ws..4 {
        r[i] = a[i - ws] << bs;
        if bs > 0 && i > ws {
            r[i] |= a[i - ws - 1] >> (64 - bs);
        }
    }
    r
}

fn shr_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let (ws, bs) = (shift / 64, shift % 64);
    let mut r = [0u64; 4];
    for i in 0..(4 - ws) {
        r[i] = a[i + ws] >> bs;
        if bs > 0 && i + ws + 1 < 4 {
            r[i] |= a[i + ws + 1] << (64 - bs);
        }
    }
    r
}

fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    r
}

fn u256_to_field<F: FieldBackend>(limbs: &[u64; 4]) -> FieldElement<F> {
    let mut result = FieldElement::<F>::from_u64(limbs[0]);
    let shift64 =
        FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
    if limbs[1] != 0 {
        result = result.add(&FieldElement::<F>::from_u64(limbs[1]).mul(&shift64));
    }
    if limbs[2] != 0 {
        let shift128 = shift64.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[2]).mul(&shift128));
    }
    if limbs[3] != 0 {
        let shift128 = shift64.mul(&shift64);
        let shift192 = shift128.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[3]).mul(&shift192));
    }
    result
}
