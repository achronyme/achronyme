//! Shared contract for constraint-system backends.
//!
//! A [`ConstraintBackend`] walks an [`IrProgram`] and emits backend-specific
//! artifacts (R1CS constraints, Plonkish columns, future AIR/STARK polynomials).
//! The trait centralises the per-instruction dispatch loop so every backend
//! handles the same [`Instruction`] variants in the same order.
//!
//! Implementors provide [`compile_instruction`](ConstraintBackend::compile_instruction);
//! the default [`compile_ir`](ConstraintBackend::compile_ir) loops over the
//! program and calls it with the instruction index.

use ir_core::{Instruction, IrProgram};
use memory::FieldBackend;

use crate::PoseidonParamsProvider;

/// Emit backend-specific constraints from a flat SSA [`IrProgram`].
pub trait ConstraintBackend<F: FieldBackend> {
    /// Backend-specific compile error.
    type Error;

    /// Compile a single IR instruction at position `ir_idx` in the program.
    ///
    /// Implementors must handle every variant of [`Instruction`].
    /// The index is exposed so backends that track provenance
    /// (e.g. `R1CSCompiler::constraint_origins`) can record it.
    fn compile_instruction(
        &mut self,
        ir_idx: usize,
        inst: &Instruction<F>,
    ) -> Result<(), Self::Error>
    where
        F: PoseidonParamsProvider;

    /// Walk the program and compile every instruction in order.
    ///
    /// Default impl iterates `program.iter().enumerate()` and calls
    /// [`compile_instruction`](Self::compile_instruction). Overridable
    /// if a backend needs program-level setup/teardown, but most
    /// backends should reuse the default.
    fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), Self::Error>
    where
        F: PoseidonParamsProvider,
    {
        for (ir_idx, inst) in program.iter().enumerate() {
            self.compile_instruction(ir_idx, inst)?;
        }
        Ok(())
    }
}
