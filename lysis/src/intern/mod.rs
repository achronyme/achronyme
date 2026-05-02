//! Hash-consing infrastructure: `NodeInterner` + `NodeId` + two-tier
//! interning policy (per-instruction, per-template-body).
//!
//! The real interner consists of: `NodeKey<F>` structural keys
//! (`key` module), the `SideEffect<F>` / `EffectId` side-channel
//! (`effect`), the span-list policy (`span`), and the `NodeInterner`
//! itself (`interner`) with the per-instruction tier wired up.
//! Materialization to a flat `Vec<InstructionKind>` lives in
//! `materialize`. The per-template-body tier sits on top once
//! template lifting is in play. See RFC §§5.1–5.6 for the contract.
//!
//! [`NodeId`], [`NodeIdGen`], [`InstructionKind`], [`Visibility`] live
//! in the `lysis-types` leaf crate so they can be consumed by both
//! `lysis` and upstream crates (`ir`, and later `ir-forge`) without a
//! dependency cycle; this module re-exports them so the
//! `lysis::intern::*` paths keep working for existing callers.

pub mod effect;
pub mod hash;
pub mod interner;
pub mod key;
pub mod materialize;
pub mod span;

pub use effect::{EffectId, SideEffect};
pub use hash::{deterministic_hash, DeterministicBuildHasher};
pub use interner::{NodeInterner, NodeMeta};
pub use key::NodeKey;
pub use lysis_types::{InstructionKind, NodeId, NodeIdGen, Visibility};
pub use span::{SpanList, SpanRange, SPAN_LIST_CAP};
