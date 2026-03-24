//! Machine module - VM implementation
//!
//! This module contains the Virtual Machine implementation segmented into
//! focused submodules for maintainability and scalability.

mod arithmetic;
mod comparison;
mod control;
mod data;
mod frame;
mod gc;
mod globals;
mod interpreter;
pub mod methods;
mod native;
mod promotion;
pub mod prototype;
pub mod prove;
mod stack;
mod upvalue;
pub mod value_ops;
mod vm;

// Public API
pub use frame::CallFrame;
pub use prove::{ProveError, ProveHandler, ProveResult, VerifyHandler};
pub use vm::{MAX_FRAMES, VM};
