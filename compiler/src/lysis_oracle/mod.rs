//! Lysis oracle — semantic-equivalence decision for Phase 3 hard gate.
//!
//! This module owns the driver side of the 4-step pipeline described in
//! `.claude/plans/lysis-vm.md` §9.1:
//!
//! 1. Canonicalize both `IrProgram<F>`s (via `ir::prove_ir::canonicalize_ssa`).
//! 2. Verify the public-input partition is bit-identical.
//! 3. Compile both to R1CS via [`crate::r1cs_backend::R1CSCompiler`] and
//!    compare the constraint sets as a multiset.
//! 4. Solve both with each test input via [`crate::witness_gen::WitnessGenerator`]
//!    and compare the resulting witness vectors.
//!
//! Lives in `compiler/` rather than `ir/` because steps 3–4 call the
//! R1CS compiler and witness generator. Step 1 is in `ir/` (pure IR
//! transformation, `ir::prove_ir::canonicalize_ssa`).

pub mod compare;

pub use compare::{semantic_equivalence, OracleResult, OracleSide};
