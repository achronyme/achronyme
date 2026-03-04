//! Carry-chain primitives for multi-limb arithmetic.
//!
//! Shared by `field` (Montgomery arithmetic) and `bigint` (fixed-width unsigned).

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
