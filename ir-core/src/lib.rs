//! # `ir-core` — Flat-SSA IR vocabulary (leaf crate)
//!
//! Holds the shared SSA IR types that both `ir` and `ir-forge` need
//! to name. The leaf-crate split exists to break what would otherwise
//! be a Cargo cycle between `ir` and `ir-forge` — see "Why it exists"
//! below.
//!
//! ## Why it exists
//!
//! `ir-forge` (the ProveIR layer + lysis interop adapters) needs to
//! produce `Instruction<F>` and name `IrProgram<F>` / `SsaVar` /
//! `IrType` / `Visibility`. If those types lived in `ir`, then
//! `ir-forge → ir`. But during migration, `ir`'s internal prove_ir
//! subtree also needed `ir-forge → ir` would create a Cargo cycle
//! with any `ir → ir-forge` shim. Extracting the shared vocabulary
//! to this leaf crate breaks the cycle: both `ir` and `ir-forge`
//! depend on `ir-core`, neither depends on the other.
//!
//! ## What lives here
//!
//! - `types` — `Instruction<F>`, `IrProgram<F>`, `IrType`, `SsaVar`,
//!   `Visibility`, and related helpers.
//! - `error` — `IrError`, `OptSpan`, `span_box`.
//!
//! Everything else (passes, lowering, evaluator, module loader,
//! inspector, stats) stays in `ir`; the ProveIR layer moves to
//! `ir-forge`.

pub mod error;
pub mod types;

pub use error::{span_box, IrError, OptSpan};
pub use types::{Instruction, IrProgram, IrType, SsaVar, Visibility};
