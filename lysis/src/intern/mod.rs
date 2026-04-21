//! Hash-consing infrastructure: `NodeInterner` + `NodeId` + two-tier
//! interning policy (per-instruction, per-template-body).
//!
//! Phase 2 lands the real interner: `NodeKey<F>` structural keys
//! (`key` module), the `SideEffect<F>` / `EffectId` side-channel
//! (`effect`), the span-list policy (`span`), and the `NodeInterner`
//! itself (`interner`) with the per-instruction tier wired up.
//! Materialization to a flat `Vec<InstructionKind>` lives in
//! `materialize`. Phase 3 adds the per-template-body tier on top.
//! See RFC §§5.1–5.6 for the contract.

pub mod hash;
pub mod key;
pub mod kind;
pub mod node;
pub mod span;

pub use hash::{deterministic_hash, DeterministicBuildHasher};
pub use key::NodeKey;
pub use kind::{InstructionKind, Visibility};
pub use node::{NodeId, NodeIdGen};
