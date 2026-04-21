//! Bytecode: opcode enum + decoder + validator.
//!
//! Phase 1 delivers:
//!
//! - [`opcode::Opcode`] — all 29 Lysis opcodes (RFC §4.3).
//! - [`const_pool::ConstPool`] — the tagged constant pool (RFC §4.4).
//! - [`encoding::encode`] / [`encoding::decode`] — round-trip the
//!   whole program.
//! - [`validate::validate`] — the 11 well-formedness rules (RFC §4.5).
//!
//! Downstream modules consume the decoded [`crate::program::Program`]
//! and never touch raw bytes again.

pub mod const_pool;
pub mod encoding;
pub mod opcode;
pub mod validate;

pub use const_pool::{ConstPool, ConstPoolEntry};
pub use encoding::{decode, encode, encode_opcode};
pub use opcode::{code, Opcode};
pub use validate::validate;
