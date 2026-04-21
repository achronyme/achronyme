//! Hash-consing infrastructure: `NodeInterner` + `NodeId` + two-tier
//! interning policy (per-instruction, per-template-body).
//!
//! Phase 1 provides `NodeId`, `NodeIdGen`, and `InstructionKind<F>`
//! so the rest of the crate can speak in terms of emitted-node
//! identifiers and IR instruction shapes. The hash-consing interner
//! itself lands in Phase 2; see RFC §5.

pub mod hash;
pub mod kind;
pub mod node;
pub mod span;

pub use kind::{InstructionKind, Visibility};
pub use node::{NodeId, NodeIdGen};
