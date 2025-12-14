pub mod error;
pub mod globals;
pub mod machine;
pub mod opcode;

pub use error::RuntimeError;
pub use globals::GlobalEntry;
pub use machine::{CallFrame, VM};
pub use opcode::OpCode;
pub mod native;
pub use native::{NativeFn, NativeObj};
pub mod stdlib;
