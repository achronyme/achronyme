extern crate self as vm;

pub mod error;
pub mod globals;
pub mod machine;
pub mod opcode;

pub use error::RuntimeError;
pub use globals::GlobalEntry;
pub use machine::prototype::known_method_names;
pub use machine::prove::ProveError;
pub use machine::value_ops::ValueOps;
pub use machine::{CallFrame, ProveHandler, ProveResult, VerifyHandler, MAX_FRAMES, VM};
pub use opcode::OpCode;
pub mod module;
pub mod native;
pub use module::{NativeDef, NativeModule};
pub use native::{MethodFn, NativeFn, NativeObj};
pub mod loader;
pub mod specs;
pub mod stdlib;
pub use loader::LoaderError;

// Re-export proc-macros so downstream crates use `vm::ach_native` / `vm::ach_module`
pub use ach_macros::{ach_module, ach_native};
