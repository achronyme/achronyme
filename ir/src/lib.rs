pub mod error;
pub mod eval;
pub mod lower;
pub mod passes;
pub mod prove_ir;
pub mod stats;
pub(crate) mod suggest;
pub mod types;

pub use error::IrError;
pub use lower::IrLowering;
pub use prove_ir::ProveIrError;
pub use types::{Instruction, IrProgram, IrType, SsaVar, Visibility};
