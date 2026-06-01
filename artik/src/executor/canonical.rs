use super::*;

// ── Canonical-representative arithmetic ─────────────────────────────────
//
// The four field-level opcodes (`FIDiv`, `FIRem`, `FShr`, `FAnd`) operate
// on the 256-bit canonical representative of a field element. Inputs are
// always `< p` (every Field cell carries a reduced value), so the
// canonical rep is also the integer value, and the result is always
// `< p` (each op is monotonically non-increasing in the operand).
//
// Layout: `[u64; 4]` little-endian — limb 0 carries the low 64 bits,
// limb 3 the high 64 bits.

/// Pad / truncate a const-pool entry to a 4-limb canonical mask. Used
/// by `FAnd` to load the mask. Bytes beyond 32 are dropped (validator
/// catches `> max_const_bytes` per backend earlier).
///
/// Asymmetry note: `PushConst` rejects const-pool bytes whose canonical
/// rep is `>= p` (via `decode_const_fe`), but this loader does not.
/// This is intentional: a mask is a bit pattern, not a field element.
/// Even if the mask's bit pattern represents `>= p`, the AND result
/// `(a < p) AND mask` is `≤ a < p`, so the output is always a valid
/// canonical rep. Adding a modular-reduction here would silently
/// change masks like `0xFF...FF` (all bits set) into something else.
pub(super) fn canonical_rep_from_bytes(bytes: &[u8]) -> [u64; 4] {
    let mut buf = [0u8; 32];
    let n = bytes.len().min(32);
    buf[..n].copy_from_slice(&bytes[..n]);
    [
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    ]
}

/// Limb-wise AND. No allocation, exact.
pub(super) fn canonical_rep_and(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

/// Right-shift the 256-bit value by `amount` bits. `amount` ∈ [0, 253]
/// is enforced by the validator; any value ≥ 256 would zero the result.
pub(super) fn canonical_rep_shr(a: [u64; 4], amount: u32) -> [u64; 4] {
    if amount >= 256 {
        return [0; 4];
    }
    let limb_shift = (amount / 64) as usize;
    let bit_shift = amount % 64;
    let mut out = [0u64; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let src_idx = i + limb_shift;
        if src_idx >= 4 {
            break;
        }
        let lo = a[src_idx] >> bit_shift;
        let hi = if bit_shift > 0 && src_idx + 1 < 4 {
            // `64 - bit_shift` is in [1, 63], so the shift is well-defined.
            a[src_idx + 1] << (64 - bit_shift)
        } else {
            0
        };
        *slot = lo | hi;
    }
    out
}

/// Convert a 4-limb canonical rep to `BigUint` for div/rem.
fn limbs_to_biguint(limbs: [u64; 4]) -> num_bigint::BigUint {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    num_bigint::BigUint::from_bytes_le(&bytes)
}

/// Convert a `BigUint` back to a 4-limb canonical rep. Pads with zero
/// limbs if the BigUint is shorter than 4 u64s; truncates higher limbs
/// (only happens for adversarial intermediate values, never for `< p`
/// inputs).
fn biguint_to_limbs(n: &num_bigint::BigUint) -> [u64; 4] {
    let bytes = n.to_bytes_le();
    let mut buf = [0u8; 32];
    let take = bytes.len().min(32);
    buf[..take].copy_from_slice(&bytes[..take]);
    [
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    ]
}

/// Truncated 256-bit unsigned division: `floor(a / b)`. Caller has
/// already verified `b != 0`.
pub(super) fn canonical_rep_div(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let abi = limbs_to_biguint(a);
    let bbi = limbs_to_biguint(b);
    biguint_to_limbs(&(abi / bbi))
}

/// 256-bit unsigned remainder: `a mod b`. Caller has already verified
/// `b != 0`.
pub(super) fn canonical_rep_rem(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let abi = limbs_to_biguint(a);
    let bbi = limbs_to_biguint(b);
    biguint_to_limbs(&(abi % bbi))
}

/// Decode a const-pool entry into a field element. The bytes are
/// stored length-prefixed and zero-padded up to the backend's canonical
/// size (32 bytes for BN-like, 8 for Goldilocks). The backend's
/// `from_le_bytes` requires exactly 32 bytes for its reject-above-p
/// check, so we pad here.
pub(super) fn decode_const_fe<F: FieldBackend>(bytes: &[u8]) -> Option<FieldElement<F>> {
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    F::from_le_bytes(&buf).map(FieldElement::<F>::from_repr)
}
