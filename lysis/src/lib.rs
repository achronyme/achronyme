//! # Lysis — Template-Instantiation VM
//!
//! Lysis is the third specialized VM in the Achronyme toolchain, joining
//! Akron (bytecode execution for the language surface) and Artik
//! (witness computation). Its job is to replace the eager
//! `ir_forge::instantiate` pipeline (3,025 LOC) with a register-based
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
pub use bytecode::{decode, encode, ConstPool, ConstPoolEntry, InputSrc, Opcode};
pub use config::LysisConfig;
pub use error::LysisError;
pub use execute::{execute, expected_family, Frame, InterningSink, IrSink, StubSink};
pub use header::{
    LysisHeader, FLAGS_DEFINED_MASK, FLAG_HAS_WITNESS_CALLS, HEADER_SIZE, HEADER_SIZE_V1,
    HEADER_SIZE_V2, MAGIC, VERSION, VERSION_V1,
};
pub use intern::{
    EffectId, InstructionKind, NodeId, NodeIdGen, NodeInterner, NodeKey, SideEffect, SpanList,
    SpanRange, Visibility,
};
pub use program::{Instr, Program, Template};

/// Forward-compat aliases. `Program` and `ProgramBuilder` collide
/// with `artik::Program` / `artik::ProgramBuilder`; `Visibility`
/// collides with `ir::Visibility` (signals) and the parser's AST
/// visibility. The post-cleanup rename (see
/// `.claude/plans/structural-cleanup.md` §10 D5) disambiguates. Use
/// these names in new code.
pub type LysisProgram<F> = Program<F>;
pub type LysisProgramBuilder<F> = ProgramBuilder<F>;
pub type BindingVisibility = Visibility;
