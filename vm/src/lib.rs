pub mod error;
pub mod globals;
pub mod machine;
pub mod opcode;

pub use error::RuntimeError;
pub use globals::GlobalEntry;
pub use machine::prove::ProveError;
pub use machine::value_ops::ValueOps;
pub use machine::{CallFrame, ProveHandler, ProveResult, VerifyHandler, MAX_FRAMES, VM};
pub use opcode::OpCode;
pub mod module;
pub mod native;
pub use module::{NativeDef, NativeModule};
pub use native::{NativeFn, NativeObj};
pub mod loader;
pub mod specs;
pub mod stdlib;
pub use loader::LoaderError;
