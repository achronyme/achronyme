//! Lysis lifter — consumes [`ExtendedInstruction<F>`] and emits Lysis
//! bytecode.
//!
//! The lifter lives in `ir` rather than `lysis` because:
//!
//! 1. The Phase 3.A bridge already establishes `ir → lysis` (see
//!    `lysis_bridge.rs` and `lysis_materialize.rs`). A reverse edge
//!    would create a dependency cycle.
//! 2. The lifter's input type is `ir::prove_ir::ExtendedInstruction<F>`
//!    — a proveIR-native structure that Lysis has no business
//!    knowing about. Pushing the lifter to `ir` keeps Lysis a leaf.
//!
//! ## Submodules
//!
//! | Module | Deliverable | RFC |
//! |---|---|---|
//! | [`symbolic`] | `SymbolicTree` + `symbolic_emit` — symbolic walk of a body with placeholder slots for loop_var-derived constants | §6.1 |
//! | `diff` (3.B.4) | `structural_diff` with AST-path slot identity | §6.1.1 |
//! | `bta` (3.B.5) | 3-point classifier | §6.1.1 |
//! | `extract` (3.B.6) | Template extraction (lambda-lifting) + `compute_frame_size` | §6.2 |
//! | `walker` (3.B.7) | Main dispatcher driving the whole pass | §6.3 |
//!
//! [`ExtendedInstruction<F>`]: crate::prove_ir::ExtendedInstruction

pub mod diff;
pub mod symbolic;

pub use diff::{structural_diff, Diff};
pub use symbolic::{symbolic_emit, OpTag, SlotId, SymbolicNode, SymbolicTree};
