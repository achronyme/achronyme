/// Poseidon Hash Function over BN254 Scalar Field
///
/// Sponge-based hash designed for arithmetic circuits.
/// Parameters: t=3 (state width), R_f=8 full rounds, R_p=57 partial rounds.
/// S-box: x^5 (alpha=5).
///
/// This implementation provides:
/// 1. Native computation (for witness generation)
/// 2. R1CS constraint synthesis (for proof circuits)
///
/// # Constant provenance
///
/// The default constructor [`PoseidonParams::bn254_t3`] uses round constants
/// and MDS matrix from **circomlibjs v0.1.7** (iden3), extracted via:
/// ```text
/// const poseidon = require("circomlibjs").buildPoseidon();
/// poseidon.C[1]  // 195 round constants for t=3
/// poseidon.M[1]  // 3x3 MDS matrix for t=3
/// ```
///
/// # Divergence from the Poseidon paper
///
/// The Poseidon paper (ePrint 2019/458, Appendix E) specifies a Grain LFSR
/// for round constant generation and Cauchy MDS construction. circomlibjs
/// uses **different** constants that do NOT match the paper's LFSR output
/// (see [iden3/circomlib#75](https://github.com/iden3/circomlib/issues/75)).
///
/// Additionally, circomlibjs returns `state[0]` as the hash output, while
/// the paper specifies output from the rate elements (`state[1..t]`).
/// We follow circomlibjs convention for ecosystem interoperability.
///
/// The paper-compliant implementation is available via
/// [`PoseidonParams::bn254_t3_lfsr`] for reference and auditing.
mod circuit;
mod constants;
mod lfsr;
mod native;
mod params;

#[cfg(test)]
mod tests;

pub use circuit::{poseidon_hash_circuit, poseidon_permutation_circuit};
pub use native::{poseidon_hash, poseidon_hash_single, poseidon_permutation};
pub use params::PoseidonParams;
