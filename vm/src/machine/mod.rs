//! Machine module - VM implementation
//!
//! This module contains the Virtual Machine implementation segmented into
//! focused submodules for maintainability and scalability.

mod arithmetic;
mod control;
mod data;
mod frame;
mod gc;
mod globals;
mod interpreter;
mod native;
mod promotion;
pub mod prove;
mod stack;
mod upvalue;
pub mod value_ops;
mod vm;

// Public API
pub use frame::CallFrame;
pub use prove::{ProveError, ProveHandler, ProveResult, VerifyHandler};
pub use vm::{MAX_FRAMES, VM};
