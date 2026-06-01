//! ExtendedInstruction walker.
//!
//! Consumes a `Vec<ExtendedInstruction<F>>` and emits a Lysis
//! `Program<F>` whose execution reproduces the original instruction
//! stream modulo the interner's hash-cons deduplication.
//!
//! ## Scope
//!
//! The walker handles:
//!
//! - `Plain(Instruction<F>)` — every arithmetic, boolean, comparison,
//!   hash, constraint, and side-effect variant. Several lower via
//!   desugarings rather than dedicated opcodes:
//!     - `Not(x)`         → `Sub(one, x)`
//!     - `And(x,y)`       → `Mul(x, y)`
//!     - `Or(x,y)`        → `Add(x,y) - Mul(x,y)`
//!     - `Assert(x)`      → `AssertEq(x, one)`
//!     - `IsNeq(x,y)`     → `Sub(one, IsEq(x, y))`
//!     - `IsLe(x,y)`      → `Sub(one, IsLt(y, x))`
//!     - `IsLtBounded`    → `IsLt` (bitwidth hint dropped)
//!     - `IsLeBounded`    → `Sub(one, IsLt(y, x))`
//!     - `WitnessCall`    → `EmitWitnessCall` with Artik blob interning
//!
//!   The `one` register is lazily allocated at the top of `lower` only
//!   when the body contains at least one desugaring that needs it.
//! - `LoopUnroll` — emits the Lysis `LoopUnroll` opcode with an
//!   inline body. The executor's loop machinery takes care of
//!   iteration binding and hash-cons dedup within the body.
//!
//! Not handled:
//!
//! - `TemplateBody` / `TemplateCall` — template extraction is wired
//!   through `extract.rs`, but the bytecode emission of
//!   `DefineTemplate` + `InstantiateTemplate` flows through a
//!   different path connected to the oracle gate. Walkers that hit
//!   these variants return `WalkError::TemplateNotSupported`; the
//!   walker driver falls back to inline unrolling when that error
//!   appears.
//! - `Div` — field division `x / y = x * y^{-1}`. Requires emitting
//!   an inline Artik blob for the inverse + a range constraint. No
//!   precedent in this walker; deferred until a use case surfaces.
//! - `IntDiv` / `IntMod` — bounded integer arithmetic; the Lysis
//!   bytecode has no opcode for these today. Circom never emits them
//!   (signal arith is field-native).
//! - Negative loop bounds — `LoopUnroll` uses `u32` in the bytecode,
//!   so negative `i64` bounds are rejected up-front.
//! - `RangeCheck` / `Decompose` with bit counts > 255 — the Lysis
//!   opcodes carry the count as `u8`.
//!
//! ## Register allocation
//!
//! Bump allocation via `lysis::lower::RegAllocator`: every SsaVar
//! that defines a fresh value gets the next register, and the
//! mapping persists for the whole program (no release). Frame size
//! is the high water mark.
//!
//! ## Top-level template wrapping
//!
//! The Lysis bytecode caps a frame at 255 registers ( "dense
//! bytecode" — frame_size is `u8`), so emitting an entire body into
//! the root frame would trip `FrameOverflow` whenever the lowered SSA
//! exceeds that width even if the underlying memory is nowhere near
//! the limit. SHA-256(64) is the canonical case.
//!
//! The walker therefore always wraps the body in Template 0. The
//! root body is the trivial sequence `InstantiateTemplate(0, [], [])`
//! followed by `Halt`, and all real work happens inside the template's
//! frame. Programs that fit in 255 regs see no behavioural change (the
//! materialized `InstructionKind` stream is identical), and programs
//! that don't get split across multiple chained templates by the split
//! machinery layered on top of this wrapping.

use rustc_hash::{FxBuildHasher, FxHashMap as HashMap, FxHashSet as HashSet};

use fixedbitset::FixedBitSet;
use lysis::bytecode::encoding::encode_opcode;
use lysis::bytecode::Opcode;
use lysis::lower::{AllocError, RegAllocator, RegId};
use lysis::program::Program;
use lysis::ProgramBuilder;
use memory::{FieldBackend, FieldElement, FieldFamily};
use std::time::Instant;

use super::extract::{lift_uniform_loops, ExtractError, TemplateRegistry, MAX_FRAME_SIZE};
use crate::extended::{IndexedEffectKind, ShiftDirection};
use crate::{ExtendedInstruction, TemplateId};
use ir_core::{Instruction, SsaVar, Visibility};

/// Hard cap on the frame size (`u8` in). The walker keeps
/// each template strictly below this — see [`reg_cost_of_emit`] for
/// the per-emit cost estimator that informs the split decision.
const FRAME_CAP: u32 = 255;
/// Margin of slack reserved on top of the cap so that the executor
/// always has room for the worst-case single emission (Decompose can
/// allocate up to 255 slots in one go; a runaway single emit surfaces
/// as a clean `FrameOverflow` error rather than a corrupt constraint
/// stream).
const FRAME_MARGIN: u32 = 0;

/// Hard cap on the total live-set size handled by a single
/// `compute_live_set` call, including spilled cold vars. Anything
/// beyond this is a structural overflow (~MB-scale program); the
/// walker errors out cleanly with `LiveSetTooLarge`. This is the
/// *hot-partition* limit — see [`MAX_CAPTURES_HOT`]. Total live sets
/// up to ~65535 fit naturally because heap slots are u16-indexed.
const MAX_CAPTURES: usize = u16::MAX as usize;

/// Hot-partition budget. The first `MAX_CAPTURES_HOT` live SSA vars
/// (sorted by *first-use* in the upcoming body window, not by
/// `SsaVar.0`) are passed as `capture_regs`; the remainder are
/// spilled to the program-global heap and reloaded lazily on first
/// use in the callee body. Setting this lower than
/// `FRAME_CAP - FRAME_MARGIN` reserves headroom for emit-time scratch
/// allocations in the new frame.
const MAX_CAPTURES_HOT: usize = 48;

/// Switch threshold between `Opcode::EmitWitnessCall` (classic,
/// register outputs) and `Opcode::EmitWitnessCallHeap` (heap outputs).
/// When a `WitnessCall` produces more than this many outputs, the
/// walker emits the heap variant because the classic path would need
/// `outputs.len()` fresh regs and exceed `FRAME_CAP = 255` structurally
/// — a single instruction whose own cost is greater than the cap
/// can't fit in any frame, no matter how much split logic is layered
/// on top.
///
/// Threshold rationale: SHA-256 emits `WitnessCall(out=256)`; this
/// constant catches that case while leaving headroom (200) for
/// witness calls with moderate output counts to still use the
/// classic path (which avoids a heap-slot per output).
const MAX_WITNESS_OUTPUTS_INLINE: usize = 200;

mod costs;
mod emit;
mod error;
mod liveness;
mod loops;
mod lower;
mod plain;
mod sizing;
mod split;
mod state;
mod symbolic;

pub use error::WalkError;
pub use state::Walker;

use costs::*;
use liveness::*;
pub(crate) use liveness::{collect_defined_ssa_vars, collect_in_extinst};
use sizing::*;
use state::TemplateBuf;

#[cfg(test)]
mod tests;
