//! Bytecode: opcode enum + decoder + validator.
//!
//! Components:
//!
//! - [`opcode::Opcode`] — all Lysis opcodes.
//! - [`const_pool::ConstPool`] — the tagged constant pool.
//! - [`encoding::encode`] / [`encoding::decode`] — round-trip the
//!   whole program.
//! - [`validate::validate`] — the well-formedness rules.
//!
//! Downstream modules consume the decoded [`crate::program::Program`]
//! and never touch raw bytes again.

pub mod const_pool;
pub mod encoding;
pub mod opcode;
pub mod validate;

pub use const_pool::{ConstPool, ConstPoolEntry};
pub use encoding::{decode, encode, encode_opcode};
pub use opcode::{code, InputSrc, Opcode};
pub use validate::validate;
