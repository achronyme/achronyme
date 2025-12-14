//! Machine module - VM implementation
//!
//! This module contains the Virtual Machine implementation segmented into
//! focused submodules for maintainability and scalability.

mod frame;
mod vm;
mod stack;
mod arithmetic;
mod control;
mod globals;
mod native;
mod promotion;
mod gc;

// Public API
pub use frame::CallFrame;
pub use vm::VM;
