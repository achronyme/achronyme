//! Bytecode validator — the pre-execution well-formedness gate
//!.
//!
//! The validator consumes a [`Program`] that has already been
//! structurally decoded (opcodes parsed, body byte-length matches
//! header, const pool entries are tag-dispatched) and enforces the
//! eleven semantic invariants from the RFC. After `validate` returns
//! `Ok`, the executor can run the program without re-checking any of
//! these properties — the bytecode is *trusted* at that point.
//!
//! # Rule coverage
//!
//! | Rule | Where |
//! |-----:|---|
//! |  1 | `LysisHeader::decode` (magic + version) |
//! |  2 | caller passes `family` to `validate_against_runtime` (off by default; executor invokes it) |
//! |  3 | `bytecode::decode` (`BodyLenMismatch`) |
//! |  4 | [`check_const_bounds`] |
//! |  5 | runtime — [`crate::execute`] (depends on captures slice) |
//! |  6 | [`check_jump_targets`] |
//! |  7 | [`check_templates_defined`] |
//! |  8 | [`check_register_bounds`] |
//! |  9 | [`check_forward_dataflow`] (linear-only; skipped when jumps present) |
//! | 10 | [`check_reachable_return`] |
//! | 11 | [`check_call_graph`] |
//! | 12 | [`check_heap_slot_bounds`] (slot < heap_size_hint) |
//! | 13 | [`check_heap_single_static_store`] (at most one StoreHeap per slot) |
//!
//! Rules 1, 3 are enforced before this module even gets a chance to
//! look at the program, so there is nothing here for them. Rule 5
//! needs the runtime captures slice; it lives in the executor.
//!
//! # Current simplifications
//!
//! Two rules admit rigorous implementations that the current
//! scaffolding approximates:
//!
//! - **Rule 9** (no uninitialized register use). Implemented as a
//!   linear scan: a register is considered initialized once written
//!   by an opcode with [`Opcode::writes_register`]. When the body
//!   contains any `Jump`/`JumpIf`, the check bails out with `Ok(())`
//!   — back-edges would require SSA-ish dataflow and the runtime
//!   [`LysisError::ReadUndefinedRegister`] safety net backstops the
//!   executor. A proper forward dataflow analysis is future work.
//!
//! - **Rule 10** (`Return` reachable from every code path). The
//!   current check demands that the last instruction of every
//!   template body (and the top-level stream) is a terminator
//!   (`Return` / `Halt` / `Trap`). Bodies with forward jumps are
//!   still accepted — a full control-flow analysis that proves all
//!   paths reach the terminator is future work.
//!
//! - **Top-level frame size**. The RFC specifies `frame_size` only
//!   for `DefineTemplate`; the top-level body has no explicit frame
//!   size. The validator treats the top-level body as having
//!   implicit `frame_size = 256` (the maximum u8 can address), so
//!   rule 8 is a tautology at top level. Inside a template body,
//!   rule 8 is enforced against that template's declared
//!   `frame_size`. A future header revision may thread an explicit
//!   `root_frame_size`.

mod call_graph;
mod consts;
mod dataflow;
mod heap;
mod jumps;
mod reachability;
mod registers;
mod templates;

#[cfg(test)]
mod tests;

use memory::field::FieldBackend;

use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::program::Program;

use call_graph::check_call_graph;
use consts::check_const_bounds;
use dataflow::check_forward_dataflow;
use heap::{check_heap_single_static_store, check_heap_slot_bounds};
use jumps::check_jump_targets;
use reachability::check_reachable_return;
use registers::check_register_bounds;
use templates::check_templates_defined;

/// Run every  rule that is *statically* decidable (i.e., that
/// does not depend on runtime captures). Rule 5 and rule 2 are the
/// executor's responsibility.
pub fn validate<F: FieldBackend>(
    program: &Program<F>,
    config: &LysisConfig,
) -> Result<(), LysisError> {
    check_const_bounds(program)?;
    check_register_bounds(program)?;
    check_jump_targets(program)?;
    check_templates_defined(program)?;
    check_forward_dataflow(program)?;
    check_reachable_return(program)?;
    check_call_graph(program, config)?;
    check_heap_slot_bounds(program)?;
    check_heap_single_static_store(program)?;
    Ok(())
}
