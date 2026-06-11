//! Bit-pattern bound inference: detects Num2Bits-style patterns in the IR
//! and infers bitwidth bounds for variables constrained by weighted boolean sums.
//!
//! ## What it detects
//!
//! When circom's `Num2Bits(n)` is inlined, it produces:
//! 1. Boolean enforcement: `bit_i * (bit_i - 1) = 0` for each bit
//! 2. Sum check: `bit_0 * 1 + bit_1 * 2 + ... + bit_{n-1} * 2^{n-1} = input`
//!
//! This pass recognizes these patterns and infers that `input` fits in `n` bits,
//! enabling downstream `IsLt`/`IsLe` to use bounded decomposition instead of
//! full 252-bit (~761 constraints per comparison).
//!
//! ## Security
//!
//! Safe-by-default: if detection fails, no bound is inferred and comparisons
//! remain unbounded (correct but more constraints). Boolean detection is sound
//! over prime fields: `v*(v-1) = 0` has exactly two solutions {0, 1}.

mod boolean;
mod detector;
mod sum;

pub(crate) use detector::detect_bit_patterns_with;
pub use detector::{detect_bit_patterns, BitPatternResult};

#[cfg(test)]
mod tests;
