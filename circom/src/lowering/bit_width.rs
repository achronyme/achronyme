//! Bit-width inference for circom-lowered `CircuitExpr`.
//!
//! Tightens the conservative `DEFAULT_MAX_BITS = 254` annotations
//! (BN254 field-width) on `Decompose`, `RangeCheck`, `BitAnd`/`BitOr`/
//! `BitXor`, `ShiftR`/`ShiftL`, and friends to the actual proven
//! upper bound of the operand. Wins:
//!
//! 1. Fewer R1CS constraints — a `Decompose(254)` becomes
//!    `Decompose(32)` for a 32-bit value, dropping ~222 bit-product
//!    constraints per operation.
//! 2. Lysis VM bytecode fits in the 255-slot frame cap for circuits
//!    that previously overflowed (SHA-256(64) is the canonical
//!    example — its `>>` operations on 32-bit words otherwise emit
//!    `SymbolicShift(num_bits=254)` which can't fit any frame).
//! 3. Faster proving downstream — fewer constraints to commit to.
//!
//! ## Soundness
//!
//! The inference is **monotone-conservative**: every rule returns an
//! upper bound on the true runtime range. Tighter is better but never
//! required for soundness — defaulting to [`BitWidth::Field`] always
//! works, just leaves potential wins on the table. Mutating an IR
//! `num_bits` field with a value tighter than its true range produces
//! incorrect constraints (silent miscompilation), so the rewrite path
//! that consumes inference results MUST never raise the inferred
//! width above the actual runtime range. The static invariant: every
//! [`BitWidth::join`] / [`BitWidth::widen`] call returns at least its
//! input.
//!
//! ## Stage 1 (leaf inference)
//!
//! This file ships with leaf-only rules — literals, captures bound to
//! literals via `LoweringContext::param_values`, `Comparison`/`BoolOp`
//! → `Exact(1)`, and bit-op merging (`BitAnd` = `min`, `BitOr`/`BitXor`
//! = `max`). No cross-template propagation, no `Num2Bits` library
//! table, no `<==` constrained-signal lookups. Stage 2 layers those
//! on top.
//!
//! Rationale for staging: Stage 1 is a pure analysis function with no
//! side effects on the lowering pipeline, ~250 LOC, easy to test in
//! isolation. Stage 2 hooks into the lowering and mutates IR
//! in-place, requiring careful regression coverage on circomlib
//! fixtures. Landing them separately keeps risk localised.

mod infer;
mod propagation;
mod rewrite;
mod scan;
mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use infer::infer_expr;
#[allow(unused_imports)]
pub use propagation::propagate_let_widths;
#[allow(unused_imports)]
pub use rewrite::{
    rewrite_num_bits_in_component_bodies, rewrite_num_bits_in_expr, rewrite_num_bits_in_node,
    rewrite_num_bits_in_prove_ir,
};
#[allow(unused_imports)]
pub use scan::scan_bool_constraints;
#[allow(unused_imports)]
pub use types::{BitWidth, InferenceCtx, SignalWidths, FIELD_BITS};
