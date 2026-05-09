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
//! ## Bytecode-Oriented Compilation
//!
//! Lysis is the canonical example of **Bytecode-Oriented Compilation
//! (BOC)** in Achronyme: a compiler architecture where the compilation
//! step is itself a bytecode program, and the *output of compilation*
//! is the side-effect of running that bytecode on a VM. The shape is
//!
//! ```text
//! Source → Bytecode → Run on VM → Compile output
//! ```
//!
//! In Lysis the output entries are SSA IR nodes that go on to become
//! R1CS constraints. This is distinct from "a compiler that emits
//! bytecode" (Java, CPython): there the bytecode is the artifact;
//! here it is the engine. The frame model, spill heap, and
//! single-static-store invariant exist because the meta-program is a
//! real program subject to real resource limits — the compiler's
//! compile-time is reified as this VM's runtime.
//!
//! ## Status
//!
//! Bytecode, executor, lifter and walker integration are in place;
//! template-body lifting and the heap spill path land progressively.

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
/// visibility. These aliases disambiguate at call sites — use them
/// in new code.
pub type LysisProgram<F> = Program<F>;
pub type LysisProgramBuilder<F> = ProgramBuilder<F>;
pub type BindingVisibility = Visibility;
