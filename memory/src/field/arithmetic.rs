// ============================================================================
// BN254 Fr Constants (from arkworks/bellman, verified)
// ============================================================================

/// The prime modulus p (BN254 Fr)
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// R = 2^256 mod p (Montgomery constant)
pub(crate) const R: [u64; 4] = [
    0xac96341c4ffffffb,
    0x36fc76959f60cd29,
    0x666ea36f7879462e,
    0x0e0a77c19a07df2f,
];

/// R^2 = (2^256)^2 mod p (for converting to Montgomery form)
pub(crate) const R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// Montgomery inverse: -p^{-1} mod 2^64
pub(crate) const INV: u64 = 0xc2e1f593efffffff;

/// p - 2 (for Fermat's little theorem inversion)
pub(crate) const P_MINUS_2: [u64; 4] = [
    0x43e1f593efffffff,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

// ============================================================================
// Low-level arithmetic helpers
// ============================================================================

/// Add with carry: (result, carry) = a + b + carry_in
#[inline(always)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let tmp = a as u128 + b as u128 + carry as u128;
    (tmp as u64, (tmp >> 64) as u64)
}

/// Subtract with borrow: (result, borrow) = a - b - borrow_in
#[inline(always)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let tmp = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (tmp as u64, (tmp >> 127) as u64) // borrow is 0 or 1
}

/// Multiply-accumulate: (lo, carry) = a * b + c + carry_in
#[inline(always)]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let tmp = a as u128 * b as u128 + c as u128 + carry as u128;
    (tmp as u64, (tmp >> 64) as u64)
}

/// Check if a >= b (4-limb comparison, little-endian).
/// NOT constant-time — only used in parsing functions (non-secret data).
#[inline]
pub(crate) fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// Conditionally subtract modulus if value >= MODULUS (constant-time).
///
/// Always performs the subtraction, then uses a branchless mask to select
/// the original or reduced value based on whether a borrow occurred.
#[inline]
pub(crate) fn subtract_modulus_if_needed(limbs: &mut [u64; 4]) {
    let (r0, borrow) = sbb(limbs[0], MODULUS[0], 0);
    let (r1, borrow) = sbb(limbs[1], MODULUS[1], borrow);
    let (r2, borrow) = sbb(limbs[2], MODULUS[2], borrow);
    let (r3, borrow) = sbb(limbs[3], MODULUS[3], borrow);

    // borrow=1 means limbs < MODULUS → keep original; borrow=0 → use reduced
    // mask = 0xFFFF...FFFF if borrow=1, 0x0000...0000 if borrow=0
    let mask = 0u64.wrapping_sub(borrow);
    limbs[0] = (limbs[0] & mask) | (r0 & !mask);
    limbs[1] = (limbs[1] & mask) | (r1 & !mask);
    limbs[2] = (limbs[2] & mask) | (r2 & !mask);
    limbs[3] = (limbs[3] & mask) | (r3 & !mask);
}

// ============================================================================
// Montgomery multiplication (CIOS — Coarsely Integrated Operand Scanning)
// ============================================================================

/// Montgomery reduction: given T (8 limbs), compute T · R⁻¹ mod p.
///
/// Algorithm: CIOS (Coarsely Integrated Operand Scanning) variant of
/// Montgomery reduction from [Çetin K. Koç, Tolga Acar, Burton S. Kaliski Jr.,
/// "Analyzing and Comparing Montgomery Multiplication Algorithms", IEEE Micro,
/// vol. 16, no. 3, pp. 26-33, June 1996]. Implementation follows the
/// bellman/ff crate pattern (zcash/ff, commit 0.13+).
///
/// Each iteration computes k = rᵢ · (-p⁻¹) mod 2⁶⁴, then adds k·p to shift
/// out one limb. After 4 iterations the lower 256 bits are zero and the upper
/// 4 limbs hold the result, which is conditionally reduced mod p.
pub(crate) fn montgomery_reduce(t: &[u64; 8]) -> [u64; 4] {
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

/// Compute a * b producing 8 limbs (schoolbook multiplication)
pub(crate) fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, hi) = mac(a[i], b[j], result[i + j], carry);
            result[i + j] = lo;
            carry = hi;
        }
        result[i + 4] = carry;
    }

    result
}

/// Montgomery multiplication: a * b * R^{-1} mod p
#[inline]
pub(crate) fn montgomery_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    montgomery_reduce(&mul_wide(a, b))
}
