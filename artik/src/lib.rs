//! # Artik — Witness Computation VM
//!
//! Artik is a dedicated, register-based VM for witness computation in
//! Achronyme circuits. It is isolated from the main Achronyme VM: no
//! shared state, no shared heap, no shared opcode tables. The two VMs
//! communicate only by value (field-element slices in, witness-slot
//! slices out).
//!
//! ## Scope (v1)
//!
//! - ~25 opcodes, Brillig-aligned plus first-class `Rotl32/Rotr32/Rotl8`
//!   for SHA-family hashing.
//! - u8 / u32 / u64 / i64 bit-exact integer arithmetic with wrapping
//!   semantics. u128 / i256 are out of scope.
//! - Multi-prime bytecode within a field family
//!   ([`FieldFamily::BnLike256`] covers BN254 + BLS12-381).
//! - No oracles / foreign calls. No JIT. No heap / GC.
//! - Mandatory bytecode validator runs on every [`decode`].
//!
//! ## Structure
//!
//! - [`ir`] — [`Instr`], [`IntW`], [`IntBinOp`], [`RegType`].
//! - [`header`] — [`ArtikHeader`]. The [`FieldFamily`] tag lives in `memory`.
//! - [`program`] — [`Program`] + [`FieldConstEntry`].
//! - [`bytecode`] — [`encode`] / [`decode`].
//! - [`validate`] — structural invariants (runs inside [`decode`]).
//! - [`executor`] — [`execute`] / [`execute_with_budget`].
//! - [`error`] — [`ArtikError`].
//!
//! [`Instr`]: ir::Instr
//! [`IntW`]: ir::IntW
//! [`IntBinOp`]: ir::IntBinOp
//! [`RegType`]: ir::RegType
//! [`ArtikHeader`]: header::ArtikHeader
//! [`FieldFamily`]: memory::FieldFamily
//! [`Program`]: program::Program
//! [`FieldConstEntry`]: program::FieldConstEntry
//! [`encode`]: bytecode::encode
//! [`decode`]: bytecode::decode
//! [`execute`]: executor::execute
//! [`execute_with_budget`]: executor::execute_with_budget
//! [`ArtikError`]: error::ArtikError

pub mod builder;
pub mod bytecode;
pub mod error;
pub mod executor;
pub mod header;
pub mod ir;
pub mod program;
pub mod validate;

pub use builder::{BuilderError, Label, ProgramBuilder};
pub use error::ArtikError;
pub use executor::{execute, execute_with_budget, ArtikContext, DEFAULT_BUDGET};
pub use header::ArtikHeader;
#[doc(inline)]
pub use memory::FieldFamily;
pub use ir::{ElemT, Instr, IntBinOp, IntW, OpTag, Reg, RegType};
pub use program::{FieldConstEntry, Program};

/// Forward-compat aliases. `Program` and `ProgramBuilder` collide
/// with `lysis::Program` / `lysis::ProgramBuilder`; the post-cleanup
/// rename (see `.claude/plans/structural-cleanup.md` §10 D5)
/// disambiguates both crates. Use these names in new code.
pub type ArtikProgram = Program;
pub type ArtikProgramBuilder = ProgramBuilder;
