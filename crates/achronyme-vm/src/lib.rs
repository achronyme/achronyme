//! Achronyme Virtual Machine
//!
//! This crate implements a register-based bytecode virtual machine for the Achronyme
//! programming language. The VM is designed to enable proper async/await support while
//! maintaining all existing language features and improving performance over the
//! tree-walker interpreter.
//!
//! # Architecture
//!
//! The VM follows a Lua 5.1-style register-based architecture with:
//! - 256 registers per call frame (8-bit addressing)
//! - Explicit call frames stored on the heap
//! - Suspension points for generators and async/await
//! - Efficient closure handling with upvalues
//!
//! # Modules
//!
//! - `opcode`: Instruction set definitions (~80 opcodes)
//! - `value`: Runtime value types (shared with evaluator)
//! - `vm`: Virtual machine execution engine
//! - `compiler`: AST to bytecode compiler
//! - `bytecode`: Bytecode format and serialization
//! - `error`: Error types for VM and compiler
//! - `builtins`: Built-in function registry and implementations

#![allow(clippy::result_large_err)]

pub mod builtins;
pub mod bytecode;
pub mod bytecode_debug;
pub mod compiler;
pub mod error;
pub mod opcode;
pub mod value;
pub mod vm;

// Re-export main types
pub use bytecode_debug::disassemble_function;
pub use compiler::Compiler;
pub use error::{CompileError, VmError};
pub use opcode::OpCode;
pub use vm::VM;

#[cfg(test)]
mod tests;
