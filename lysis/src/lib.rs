//! # Lysis — Template-Instantiation VM
//!
//! Lysis is the third specialized VM in the Achronyme toolchain, joining
//! Akron (bytecode execution for the language surface) and Artik
//! (witness computation). Its job is to replace the eager
//! `ir::prove_ir::instantiate` pipeline (3,025 LOC) with a register-based
//! bytecode pipeline that uses hash-consing and binding-time analysis to
//! avoid the multiplicative-amplification class of bugs which OOM
//! SHA-256(64) at 6.4 GB peak RSS today.
//!
//! The name comes from the Greek *λύσις* — "resolution / dissolution" —
//! fitting the triad akron (summit/endpoint) + artik
//! (articulation/proper fit) + lysis (resolution).
//!
//! ## Status
//!
//! Phase 0 (scaffolding): crate skeleton, [`LysisHeader`] with the
//! canonical 16-byte layout, and hand-written bytecode fixtures for
//! Phase 1 decoder/validator tests. No lowering, no interning, no
//! execution yet — those land in Phases 2-5 per the RFC in
//! `.claude/plans/lysis-vm.md`.
//!
//! [`LysisHeader`]: header::LysisHeader

pub mod builder;
pub mod bytecode;
pub mod error;
pub mod execute;
pub mod header;
pub mod intern;
pub mod lower;

pub use error::LysisError;
pub use header::{LysisHeader, HEADER_SIZE, MAGIC, VERSION};

// Re-export FieldFamily from artik — the canonical owner of the field
// family enum. See RFC §4.2 + §4.4 (Option Y): a Lysis-only consumer
// does not need to know the tag comes from artik.
pub use artik::FieldFamily;
