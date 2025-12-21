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
mod promotion;
mod stack;
mod vm;

// Public API
pub use frame::CallFrame;
pub use vm::VM;
