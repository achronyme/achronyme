//! Phase III — snarkjs Golden Cross-Validation
//!
//! Independent verification of Achronyme's R1CS + witness output using snarkjs
//! as an external oracle. For each circuit:
//!
//!   1. Compile with Achronyme → .r1cs + .wtns (iden3 binary format)
//!   2. `snarkjs r1cs info`  → validates R1CS structural integrity
//!   3. `snarkjs wtns check` → **independent** constraint satisfaction verification
//!   4. `snarkjs wtns export json` → extract wire values, compare against golden vectors
//!   5. (Poseidon) Full Groth16 prove + verify cycle
//!
//! This is the strongest possible correctness guarantee: an audited third-party
//! tool (snarkjs, iden3, GPL-3.0) independently certifies that our witness
//! satisfies our constraints, and wire values match industry golden vectors.
//!
//! All tests gracefully skip if snarkjs is not available.

#[path = "snarkjs_cross_validation/arithmetic.rs"]
mod arithmetic;
#[path = "snarkjs_cross_validation/benchmark.rs"]
mod benchmark;
#[path = "snarkjs_cross_validation/boolean.rs"]
mod boolean;
#[path = "snarkjs_cross_validation/comparison.rs"]
mod comparison;
#[path = "snarkjs_cross_validation/helpers.rs"]
mod helpers;
#[path = "snarkjs_cross_validation/merkle.rs"]
mod merkle;
#[path = "snarkjs_cross_validation/poseidon.rs"]
mod poseidon;
