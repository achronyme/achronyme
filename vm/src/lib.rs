pub mod opcode;
pub mod machine;
pub mod error;

pub use opcode::OpCode;
pub use machine::{VM, CallFrame};
pub use error::RuntimeError;
