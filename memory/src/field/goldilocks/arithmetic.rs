// ============================================================================
// Goldilocks Constants
// ============================================================================

/// The prime modulus: p = 2^64 - 2^32 + 1
pub(super) const P: u64 = 0xFFFFFFFF00000001;

/// ε = 2^32 - 1. Key identity: 2^64 ≡ ε (mod p).
pub(super) const EPSILON: u64 = 0xFFFFFFFF;

/// p - 2, for Fermat's little theorem inversion.
pub(super) const P_MINUS_2: [u64; 4] = [0xFFFFFFFEFFFFFFFF, 0, 0, 0];

// ============================================================================
// Fast modular reduction
// ============================================================================

/// Reduce a u128 value modulo p using the Goldilocks identity 2^64 ≡ ε (mod p).
///
/// Two-step reduction (no division):
/// 1. x = x_hi·2^64 + x_lo ≡ x_hi·ε + x_lo (mod p)  → fits in ~96 bits
/// 2. t = t_hi·2^64 + t_lo ≡ t_hi·ε + t_lo (mod p)  → fits in ~65 bits
/// 3. One conditional subtraction of p.
///
/// Fully constant-time (branchless).
#[inline]
pub(super) fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;

    // Step 1: x ≡ x_hi * ε + x_lo (mod p)
    let t: u128 = (x_hi as u128) * (EPSILON as u128) + (x_lo as u128);

    let t_lo = t as u64;
    let t_hi = (t >> 64) as u64; // ≤ 2^32

    // Step 2: t ≡ t_hi * ε + t_lo (mod p)
    // t_hi * ε ≤ 2^32 * (2^32 - 1) < 2^64, fits in u64
    let (res, carry) = t_lo.overflowing_add(t_hi.wrapping_mul(EPSILON));

    // If carry: true value = res + 2^64 ≡ res + ε (mod p).
    // When carry occurs, res < 2^64 - 2^32, so res + ε < 2^64. No overflow.
    let res = res.wrapping_add((carry as u64).wrapping_mul(EPSILON));

    // Conditional subtraction: res < 2p, so at most one subtract.
    let (r, borrow) = res.overflowing_sub(P);
    let mask = 0u64.wrapping_sub(borrow as u64);
    (res & mask) | (r & !mask)
}

// ============================================================================
// Modular arithmetic (constant-time)
// ============================================================================

/// (a + b) mod p.
#[inline]
pub(super) fn gl_add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    // If carry: sum wrapped, add ε (since 2^64 ≡ ε mod p). Result < p, no further reduce.
    // If no carry: sum might be ≥ p, conditional subtract.
    let adj = sum.wrapping_add((carry as u64).wrapping_mul(EPSILON));
    let (r, borrow) = adj.overflowing_sub(P);
    let mask = 0u64.wrapping_sub(borrow as u64);
    (adj & mask) | (r & !mask)
}

/// (a - b) mod p.
#[inline]
pub(super) fn gl_sub(a: u64, b: u64) -> u64 {
    let (r, borrow) = a.overflowing_sub(b);
    // If borrow: add p back.
    let mask = 0u64.wrapping_sub(borrow as u64);
    r.wrapping_add(P & mask)
}

/// (a * b) mod p.
#[inline]
pub(super) fn gl_mul(a: u64, b: u64) -> u64 {
    reduce128(a as u128 * b as u128)
}

/// (-a) mod p.
#[inline]
pub(super) fn gl_neg(a: u64) -> u64 {
    // Constant-time: compute p - a, then zero-mask if a was 0.
    let is_nonzero = (a | a.wrapping_neg()) >> 63;
    let mask = 0u64.wrapping_sub(is_nonzero);
    P.wrapping_sub(a) & mask
}
