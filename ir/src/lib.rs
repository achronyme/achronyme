pub mod types;
pub mod error;
pub mod lower;
pub mod passes;

pub use types::{SsaVar, Instruction, Visibility, IrProgram};
pub use error::{IrError, SourceSpan};
pub use lower::IrLowering;
