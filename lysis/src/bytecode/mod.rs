//! Bytecode: opcode enum + decoder + validator.
//!
//! Phase 1 (encode/decode for all 29 opcodes) and Phase 2 (well-formedness
//! validator, 11 rules) land here. This mod file exists so the crate
//! tree matches RFC §3.2 from the start; submodules are currently empty
//! and will be populated per the phase plan in RFC §10.

pub mod encoding;
pub mod validate;
