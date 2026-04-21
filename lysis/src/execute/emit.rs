//! Emit-IR opcode handlers — the executor's output side. Every emit
//! opcode routes through here to the interner; side-effect-wall
//! opcodes (`AssertEq`, `RangeCheck`, `WitnessCall`) bypass interning.
//!
//! Phases 1-2.
