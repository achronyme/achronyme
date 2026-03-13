pub mod error;
pub mod eval;
pub mod lower;
pub mod passes;
pub(crate) mod suggest;
pub mod types;

pub use error::IrError;
pub use lower::IrLowering;
pub use types::{Instruction, IrProgram, IrType, SsaVar, Visibility};
