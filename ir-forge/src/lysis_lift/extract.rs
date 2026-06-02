//! Template extraction (lambda-lifting).
//!
//! Takes a [`SymbolicTree`] that BTA classified as
//! [`BindingTime::Uniform`] and produces a [`TemplateSpec`] the
//! walker can emit as `DefineTemplate` bytecode plus one
//! `InstantiateTemplate` (or `LoopRolled`) per call site.
//!
//! ## What this module does now
//!
//! - Resolves the **capture layout**: slot captures (from probe
//!   bindings) come first, followed by unique `OuterRef` captures
//!   in first-appearance order. Both share the single `u8`
//!   `LoadCapture` index space that the bytecode uses.
//! - Computes a **conservative `frame_size`** by counting the nodes
//!   that will occupy a register during emission. Captures live in
//!   `r0..r{n_params-1}`; everything else bumps a fresh slot.
//! - Allocates fresh [`TemplateId`]s via a
//!   [`TemplateRegistry`] that also stores the skeleton for the
//!   walker's later bytecode-emission pass.
//!
//! ## What lives in a later iteration
//!
//! - **Canonical bytecode hash-based dedup**: deduplicating two
//!   templates whose emitted bytecode is byte-identical. The current
//!   pass allocates a fresh id for every extraction instead; a future
//!   pass will hash the emitted bytecode and merge matches. This is
//!   a size-not-correctness optimization — a pair of redundant
//!   templates just costs extra metadata, they don't produce wrong
//!   constraints.
//! - **True liveness-based frame sizing**: we over-allocate today
//!   (one slot per producing node). A future pass will do
//!   linear-scan liveness.

mod error;
mod layout;
mod lift;
mod registry;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
use super::bta::BindingTime;
#[allow(unused_imports)]
use super::symbolic::SymbolicTree;
#[allow(unused_imports)]
use crate::TemplateId;

pub use error::{ExtractError, MAX_FRAME_SIZE};
pub use layout::{build_capture_layout, compute_frame_size, CaptureKind, CaptureLayout};
pub use lift::lift_uniform_loops;
pub use registry::{extract_template, TemplateRegistry, TemplateSpec};
