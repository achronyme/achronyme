//! Lysis lifter — consumes [`ExtendedInstruction<F>`] and emits Lysis
//! bytecode.
//!
//! The emitted program is the Bytecode-Oriented Compilation (BOC) form
//! of the source circuit: when the Lysis VM executes it, the
//! side-effect is the SSA IR that the rest of the pipeline consumes.
//! This module is the AST→Bytecode half of the BOC pipeline; the
//! corresponding Run-on-VM→Compile-output half lives in the `lysis`
//! crate.
//!
//! The lifter lives in `ir` rather than `lysis` because:
//!
//! 1. An `ir → lysis` bridge already exists (see `lysis_bridge.rs`
//!    and `lysis_materialize.rs`). A reverse edge would create a
//!    dependency cycle.
//! 2. The lifter's input type is `ir::prove_ir::ExtendedInstruction<F>`
//!    — a proveIR-native structure that Lysis has no business
//!    knowing about. Pushing the lifter to `ir` keeps Lysis a leaf.
//!
//! ## Submodules
//!
//! | Module | Deliverable | RFC |
//! |---|---|---|
//! | [`symbolic`] | `SymbolicTree` and `symbolic_emit` — symbolic walk of a body with placeholder slots for loop_var-derived constants | |
//! | `diff` | `structural_diff` with AST-path slot identity | |
//! | `bta` | 3-point classifier | |
//! | `extract` | Template extraction (lambda-lifting) and `compute_frame_size` | |
//! | `walker` | Main dispatcher driving the whole pass | |
//!
//! [`ExtendedInstruction<F>`]: crate::prove_ir::ExtendedInstruction

pub mod bta;
pub mod diff;
pub mod extract;
pub mod symbolic;
pub mod walker;

pub use bta::{classify, classify_loop_unroll, BindingTime, ClassificationDetails};
pub use diff::{structural_diff, Diff};
pub use extract::{
    build_capture_layout, compute_frame_size, extract_template, lift_uniform_loops, CaptureKind,
    CaptureLayout, ExtractError, TemplateRegistry, TemplateSpec,
};
pub use symbolic::{symbolic_emit, OpTag, SlotId, SymbolicNode, SymbolicTree};
pub use walker::{WalkError, Walker};
