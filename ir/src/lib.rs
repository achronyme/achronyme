pub mod error;
pub mod eval;
pub mod inspector;
pub mod lower;
pub mod module_loader;
pub mod passes;
pub mod prove_ir;
pub mod resolver_adapter;
pub mod stats;
pub(crate) mod suggest;
pub mod types;

pub use error::IrError;
pub use lower::IrLowering;
pub use prove_ir::ProveIrError;
pub use types::{Instruction, IrProgram, IrType, SsaVar, Visibility};

/// Forward-compat alias. `Visibility` collides with `lysis::Visibility`
/// (node-interning binding) and the parser's AST visibility. In the
/// post-cleanup rename (see `.claude/plans/structural-cleanup.md` §10
/// D5) this enum becomes `SignalVisibility` to reflect that it
/// describes R1CS signal (public / witness) visibility. Use the new
/// name in new code.
pub type SignalVisibility = Visibility;
