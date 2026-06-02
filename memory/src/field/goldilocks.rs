//! Goldilocks prime field (p = 2^64 - 2^32 + 1) backend — direct `u64` arithmetic.
//!
//! Unlike BN254/BLS12-381 which use Montgomery form over `[u64; 4]`, Goldilocks
//! uses plain modular arithmetic on a single `u64`. The special structure of the
//! prime (p = 2^64 - 2^32 + 1) allows fast reduction: since 2^64 ≡ 2^32 - 1 (mod p),
//! a 128-bit product can be reduced in two steps without division.

mod arithmetic;
mod backend;

pub use backend::GoldilocksFr;

#[cfg(test)]
mod tests;
