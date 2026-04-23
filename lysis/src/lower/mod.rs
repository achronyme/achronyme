//! Lowering-side primitives that the Lysis lifter uses.
//!
//! This module holds the **leaf** pieces of the lowering machinery
//! (RFC §6): data structures that operate on Lysis-native types only.
//! Everything that consumes `ir_forge::ExtendedInstruction<F>` —
//! the walker, BTA, symbolic emission, structural diff, template
//! extraction — lives under `ir_forge::lysis_lower` because the
//! Phase 3.A bridge already points `ir → lysis`; a `lysis → ir` edge
//! would create a dependency cycle.
//!
//! What stays here:
//!
//! - [`env`] — scoped capture map (`ScopedMap<String, RegId>`) with
//!   Tarjan-stack semantics (RFC §6.4).
//! - [`alloc`] — frame register allocator (RFC §6.2).
//!
//! What lives on the `ir` side (landing through Phase 3.B.3–3.B.7):
//!
//! - symbolic emission + structural diff
//! - binding-time classifier
//! - template extraction / lambda-lifting
//! - the main walker that consumes `ExtendedInstruction<F>`

pub mod alloc;
pub mod env;

pub use alloc::{AllocError, RegAllocator, MAX_FRAME_SIZE};
pub use env::{RegId, ScopedMap, ScopedMapError};
