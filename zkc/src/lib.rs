//! ZK constraint compiler.
//!
//! Lowers the flat SSA `IrProgram<F>` produced by `ir`/`ir-forge` into:
//! - **R1CS** — the production constraint system used by Groth16, with
//!   linear-elimination + DEDUCE optimisation.
//! - **Plonkish** — column-cell encoding for KZG / halo2-style provers.
//!
//! Plus the supporting layers: `witness` (op log + replay), `r1cs_witness`
//! (R1CS-specific generator), `r1cs_gadgets` (shared helpers), `error`,
//! and `lysis_oracle` (A/B against the legacy instantiate path).
//!
//! Modules land in subsequent commits as `compiler/src/{r1cs_backend,
//! plonkish_backend, lysis_oracle, ...}` migrate over.
