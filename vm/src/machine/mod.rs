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
mod native;
pub mod prove;
mod promotion;
mod stack;
mod vm;

// Public API
pub use frame::CallFrame;
pub use prove::{ProveError, ProveHandler, ProveResult};
pub use vm::VM;
