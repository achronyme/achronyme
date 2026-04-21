//! Bytecode executor — register-based dispatch loop that emits into the
//! running `NodeInterner`.
//!
//! Phase 1 deliverable (skeleton) + Phase 2 (interner wiring). See RFC
//! §4.1 for the hybrid register-VM-with-call-stack model.

pub mod emit;
pub mod frame;
