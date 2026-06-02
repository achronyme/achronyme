//! Phase II — Comparison Operations Vectors (R1CS, BN254 Fr)
//!
//! Industry-sourced test vectors for IsEq, IsNeq, IsLt, IsLe instructions
//! with boundary value analysis and constraint count benchmarking.
//!
//! Industry sources:
//!   - circomlib comparators.circom:  https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom
//!     LessThan, GreaterThan, IsEqual gadgets for R1CS. (GPL-3.0)
//!   - Constraint-Efficient Comparators via Weighted Accumulation (MDPI):
//!     https://www.mdpi.com/2227-7390/13/24/3959  [ref 32]
//!     Optimal Num2Bits decomposition (~65 constraints for 64-bit IsLt).
//!   - Noir stdlib field/mod.nr:     https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!     lt, lte comparison operations on BN254 Fr. (MIT/Apache-2.0) [ref 44]
//!   - gnark std comparators:        https://github.com/Consensys/gnark
//!     api.Cmp() — ~65 constraints for 64-bit comparison. (Apache-2.0) [ref 14]
//!   - 0xPARC zk-bug-tracker:        https://github.com/0xPARC/zk-bug-tracker
//!     Dark Forest LessThan vulnerability: omitted bit length restriction allowed
//!     overflow attacks with forged proofs. [ref 33]
//!
//! Key benchmark (Table 1 from research document):
//!   - IsLt 64-bit: Circom ~65, Gnark ~65, Achronyme ~760 constraints
//!   - This 12× gap is weakness D7 (STRATEGY.md), tracked by constraint count tests below.
//!
//! Note: only numerical test vectors (not code) are referenced here.
//! These are facts, not copyrightable expression — compatible with our Apache-2.0.

#[path = "comparison_vectors/helpers.rs"]
mod helpers;

/// Macro for parameterized comparison tests.
macro_rules! comparison_tests {
    ($(($name:ident, $source:expr, $inputs:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                crate::helpers::compile_and_verify($source, $inputs);
            }
        )*
    };
}

#[path = "comparison_vectors/bounded_counts.rs"]
mod bounded_counts;
#[path = "comparison_vectors/equality.rs"]
mod equality;
#[path = "comparison_vectors/mixed_properties.rs"]
mod mixed_properties;
#[path = "comparison_vectors/ordering.rs"]
mod ordering;
#[path = "comparison_vectors/soundness_logic.rs"]
mod soundness_logic;
