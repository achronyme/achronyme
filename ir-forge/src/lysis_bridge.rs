//! Bridge from Lysis's mirror [`InstructionKind<F>`] back to
//! the canonical [`Instruction<F>`].
//!
//! ## Why the mirror exists
//!
//! The Lysis VM deliberately keeps a mirror [`InstructionKind<F>`]
//! in the `lysis-types` leaf crate so new emitters can come online
//! without depending on `ir` (which transitively pulls the full
//! parser / diagnostics / resolve / compile tree). That decision
//! left open how the bytecode-driven emission path would eventually
//! feed the R1CS backend, whose signature is
//! `compile_ir(&IrProgram<F>) where IrProgram<F>: uses Instruction<F>`.
//!
//! ## Why the bridge lives in `ir`
//!
//! Rust's orphan rule requires `impl<..> From<A> for B` to be
//! defined in the crate that owns `A` or `B`. Since `Instruction<F>`
//! lives in `ir`, the `From` direction goes here. `ir` depends on
//! `lysis-types` for the mirror surface - a cheap leaf dep. `lysis`
//! is not needed just for the types anymore, though `ir` still pulls
//! in the full `lysis` crate because the walker (P7a's job) lives
//! here and uses the Lysis runtime (Program, ProgramBuilder,
//! executor, bytecode codec).
//!
//! ## Conversion shape
//!
//! Every `InstructionKind<F>` variant has a 1:1 counterpart in
//! `Instruction<F>` by name and field layout - that was the point
//! of the mirror. The only non-trivial bit is [`NodeId`] ->
//! [`SsaVar`]: `NodeId` is a `NonZeroU64` one-based handle with a
//! zero-based `index()` accessor, while `SsaVar` is a plain
//! `u64` newtype. Converting via `SsaVar(id.index() as u64)` maps
//! the interner's insertion order directly onto the SSA var
//! numbering the backend expects.
//!
//! [`Instruction<F>`]: ir_core::Instruction
//! [`InstructionKind<F>`]: lysis_types::InstructionKind
//! [`NodeId`]: lysis_types::NodeId
//! [`SsaVar`]: ir_core::SsaVar

mod by_ref;
mod owned;
mod shared;

pub use by_ref::instruction_from_kind;
pub use owned::instruction_from_kind_owned;
pub use shared::ssa_var_from_node_id;

#[cfg(test)]
mod tests;
