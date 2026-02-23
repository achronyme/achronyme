pub mod error;
pub mod eval;
pub mod lower;
pub mod passes;
pub mod types;

pub use error::{IrError, SourceSpan};
pub use lower::IrLowering;
pub use types::{Instruction, IrProgram, SsaVar, Visibility};
