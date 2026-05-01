//! ZK constraint compiler.
//!
//! Lowers the flat SSA `IrProgram<F>` produced by `ir`/`ir-forge` into:
//! - **R1CS** ([`r1cs_backend`]) — the production constraint system used
//!   by Groth16, with linear-elimination + DEDUCE optimisation.
//! - **Plonkish** ([`plonkish_backend`]) — column-cell encoding for KZG /
//!   halo2-style provers.
//!
//! Plus the supporting layers:
//! - [`witness`] — `WitnessOp` log + replay machinery (formerly
//!   `akronc::witness_gen`).
//! - [`r1cs_witness`] — R1CS-specific witness generator over `WitnessOp`.
//! - [`r1cs_gadgets`] — shared gadget helpers (power-of-two, etc.).
//! - [`error`] — `R1CSError` + related types (formerly
//!   `akronc::r1cs_error`).
//! - [`lysis_oracle`] — A/B oracle that compares Lysis-lowered programs
//!   against the legacy instantiate path.

pub mod error;
pub mod lysis_oracle;
pub mod plonkish_backend;
pub mod r1cs_backend;
pub mod r1cs_gadgets;
pub mod r1cs_witness;
pub mod witness;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
