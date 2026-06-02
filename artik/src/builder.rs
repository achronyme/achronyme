//! Programmatic construction of Artik [`Program`]s.
//!
//! The circom witness-lift pass emits Artik bytecode while walking a
//! function AST. Writing the raw `Instr` list by hand is viable (the
//! executor tests do it) but gets tedious for real programs, especially
//! with forward jumps and multiple subprograms. This module provides a
//! builder with:
//!
//! - Automatic register / signal / witness-slot id allocation.
//! - A label mechanism for forward jumps (`place` fills in an offset
//!   that is only known once later instructions are emitted).
//! - Ergonomic `emit_*` helpers for common shapes (field ops, int
//!   ops, conversions) that both allocate a fresh destination
//!   register and emit the instruction in one call.
//! - Multi-subprogram support: [`ProgramBuilder::reserve_subprogram`]
//!   hands out a callable id (so a caller can emit a `Call` to a
//!   subprogram whose body is not built yet), and
//!   [`ProgramBuilder::begin_subprogram`] /
//!   [`ProgramBuilder::end_subprogram`] switch which subprogram the
//!   emission helpers target. A builder that never reserves a
//!   subprogram produces exactly one entry subprogram — identical to
//!   the single-body programs every current producer emits.
//!
//! Example usage — lift `function sq(x) { return x * x; }`:
//!
//! ```ignore
//! use artik::builder::ProgramBuilder;
//! use memory::FieldFamily;
//!
//! let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
//! let x_sig = b.alloc_signal();           // caller binds x to signal 0
//! let slot = b.alloc_witness_slot();      // caller reads slot 0
//! let x = b.read_signal(x_sig);
//! let sq = b.fmul(x, x);
//! b.write_witness(slot, sq);
//! b.ret();
//! let prog = b.finish();
//! ```
//!
//! After `finish()`, round-trip the program through
//! [`bytecode::encode`](crate::bytecode::encode) +
//! [`bytecode::decode`](crate::bytecode::decode) to run the validator.

use memory::FieldFamily;

use crate::ir::{Instr, RegType};
use crate::program::FieldConstEntry;

mod error;
mod finish;
mod labels;
mod lifecycle;
mod ops;

pub use error::BuilderError;

/// An opaque handle to a yet-to-be-placed location in the instruction
/// stream. Obtained via [`ProgramBuilder::new_label`]; materialized
/// into a byte offset by [`ProgramBuilder::place`]. Labels are
/// subprogram-local.
#[derive(Debug, Clone, Copy)]
pub struct Label(u32);

struct PendingJump {
    /// Index into the subprogram body of the Jump / JumpIf whose
    /// `target` we must patch.
    instr_index: u32,
    /// Which label this jump targets.
    label: u32,
}

/// Mutable per-subprogram emission state. Registers, the instruction
/// body, the label table, and pending jumps are all subprogram-local;
/// the constant pool and signal / witness-slot namespaces are
/// program-global and live on [`ProgramBuilder`].
struct SubInProgress {
    params: Vec<RegType>,
    returns: Vec<RegType>,
    body: Vec<Instr>,
    next_reg: u32,
    label_positions: Vec<Option<u32>>,
    pending_jumps: Vec<PendingJump>,
}

impl SubInProgress {
    fn new(params: Vec<RegType>, returns: Vec<RegType>) -> Self {
        // Parameter values are delivered into registers
        // `0..params.len()` by the executor on entry to the call, so
        // freshly allocated registers must start past them.
        let next_reg = params.len() as u32;
        Self {
            params,
            returns,
            body: Vec::new(),
            next_reg,
            label_positions: Vec::new(),
            pending_jumps: Vec::new(),
        }
    }
}

/// Captured state of the active subprogram, usable as a rollback point
/// for speculative emission (e.g. a loop-unroll attempt that may bail).
/// Produced by [`ProgramBuilder::snapshot`] and consumed by
/// [`ProgramBuilder::restore`]. A snapshot is only valid while the same
/// subprogram is active.
#[derive(Debug, Clone, Copy)]
pub struct BuilderSnapshot {
    active: usize,
    body_len: usize,
    const_pool_len: usize,
    next_reg: u32,
    next_signal: u32,
    next_slot: u32,
    label_positions_len: usize,
    pending_jumps_len: usize,
}

/// Fluent builder for [`Program`](crate::program::Program).
///
/// All emission methods target the *active* subprogram (the entry
/// subprogram until [`Self::begin_subprogram`] switches it). `finish()`
/// consumes the builder, resolves every subprogram's jump targets, and
/// returns the assembled `Program`.
pub struct ProgramBuilder {
    family: FieldFamily,
    const_pool: Vec<FieldConstEntry>,
    next_signal: u32,
    next_slot: u32,
    subs: Vec<SubInProgress>,
    active: usize,
}

#[cfg(test)]
mod tests;
