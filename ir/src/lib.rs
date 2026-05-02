pub use ir_core::{error, types};
pub use ir_forge::{module_loader, resolver_adapter};

pub mod eval;
pub mod inspector;
pub mod lower;
pub mod passes;
pub mod stats;

pub use ir_core::{Instruction, IrError, IrProgram, IrType, SsaVar, Visibility};
pub use lower::IrLowering;

/// Disambiguating alias. `Visibility` collides with `lysis::Visibility`
/// (node-interning binding) and the parser's AST visibility.
/// `SignalVisibility` reflects that this enum describes R1CS signal
/// (public / witness) visibility; prefer it in new code when both
/// names are in scope.
pub type SignalVisibility = Visibility;
