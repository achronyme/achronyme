//! Hash-consing infrastructure: `NodeInterner` + `NodeId` + two-tier
//! interning policy (per-instruction, per-template-body).
//!
//! Phase 2 deliverable. Left empty in Phase 0; the crate tree anticipates
//! the layout from RFC §3.2 so that subsequent phases add content without
//! restructuring.

pub mod hash;
pub mod span;
