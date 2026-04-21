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
//! Phase 1 (bytecode + executor skeleton) is in progress. The RFC in
//! `.claude/plans/lysis-vm.md` is the authoritative design; crate layout
//! follows RFC §3.2 and the opcode/const-pool/validator details follow
//! RFC §4.

pub mod builder;
pub mod bytecode;
pub mod config;
pub mod error;
pub mod execute;
pub mod header;
pub mod intern;
pub mod lower;
pub mod program;

pub use builder::ProgramBuilder;
pub use bytecode::{decode, encode, ConstPool, ConstPoolEntry, Opcode};
pub use config::LysisConfig;
pub use error::LysisError;
pub use execute::{execute, expected_family, Frame, IrSink, StubSink};
pub use header::{
    LysisHeader, FLAGS_DEFINED_MASK, FLAG_HAS_WITNESS_CALLS, HEADER_SIZE, MAGIC, VERSION,
};
pub use intern::{InstructionKind, NodeId, NodeIdGen, Visibility};
pub use program::{Instr, Program, Template};

// Re-export FieldFamily from artik — the canonical owner of the field
// family enum. See RFC §4.2 + §4.4 (Option Y): a Lysis-only consumer
// does not need to know the tag comes from artik.
pub use artik::FieldFamily;
