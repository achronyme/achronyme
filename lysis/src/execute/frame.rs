//! Call-stack frame layout — each frame holds its own register file (up
//! to 256 regs per frame); a separate stack holds frames for nested
//! template calls.
//!
//! Phase 1 deliverable (RFC §4.1).
