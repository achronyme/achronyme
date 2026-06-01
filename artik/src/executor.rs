//! Artik interpreter — executes a decoded, validated [`Program`]
//! against a caller-provided [`ArtikContext`].
//!
//! The executor is intentionally minimal. It does not allocate on the
//! heap after setup (arrays are bump-allocated into a single `Vec`,
//! registers live in one flat frame) and it never shares state with
//! the main Achronyme VM. Signals are read-only; witness slots are the
//! only output channel.
//!
//! # Trap model
//!
//! The bytecode validator catches *structural* errors before a program
//! ever reaches the interpreter. The executor only needs to handle
//! *data-dependent* failures:
//!
//! - [`ArtikError::FieldDivByZero`] — `FDiv`/`FInv` on zero.
//! - [`ArtikError::ArrayIndexOutOfBounds`] — dynamic index past `len`.
//! - [`ArtikError::SignalOutOfBounds`] / [`ArtikError::WitnessSlotOutOfBounds`]
//!   — signal or slot index beyond what the caller supplied.
//! - [`ArtikError::UndefinedRegister`] — a read hit a register that had
//!   no prior write on the executed path. (The validator only enforces
//!   category consistency across *writes*; dynamic branches can still
//!   leave a slot unassigned.)
//! - [`ArtikError::ExecTrap`] — explicit [`Instr::Trap`] fires.
//! - [`ArtikError::BudgetExhausted`] — loop guard.
//!
//! All cases abort cleanly; the caller's witness buffer is left in
//! whatever state the partial execution produced. It is the caller's
//! responsibility to discard the proof attempt on any `Err`.

use std::collections::HashMap;

use memory::field::{FieldBackend, FieldElement, PrimeId};
use memory::FieldFamily;

use crate::error::ArtikError;
use crate::ir::{ElemT, Instr, IntBinOp, IntW};
use crate::program::Program;

/// Default cap for the interpreter's instruction counter. Sized for
/// the heaviest realistic witness program: a 256-bit modular
/// inversion (Fermat: a modular exponentiation with a ~256-bit
/// exponent ≈ 255 modular squarings, each a multi-limb multiply plus
/// a long-division reduction) runs on the order of 1–3·10⁷
/// instructions. The cap is set well above that with headroom for
/// larger fields and heavier helpers, while still bounding runaway
/// bytecode — a non-terminating loop trips this in well under a
/// second of interpreter time. Lighter gadgets are far below it (one
/// SHA-256 round ≈ 64 instructions; a full block ≈ 4K; SHA-256 over a
/// 64-byte message well under 32K). Callers needing a different bound
/// use [`execute_with_budget`].
pub const DEFAULT_BUDGET: u64 = 100_000_000;

/// Cumulative cap on array cells allocated across a single
/// [`execute`] call. 16M cells corresponds to ~512 MB for BN-like
/// field arrays (32 B per element) or ~128 MB for U32 arrays. A
/// program can still carve that up across many [`Instr::AllocArray`]
/// calls, but it cannot exceed the sum.
pub const MAX_ARRAY_MEMORY_CELLS: u64 = 1 << 24;

/// Read-only signals + mutable witness slots the Artik program will
/// touch. The executor never reads outside these two slices and never
/// shares them with other callers.
pub struct ArtikContext<'a, F: FieldBackend> {
    pub signals: &'a [FieldElement<F>],
    pub witness_slots: &'a mut [FieldElement<F>],
}

impl<'a, F: FieldBackend> ArtikContext<'a, F> {
    pub fn new(signals: &'a [FieldElement<F>], witness_slots: &'a mut [FieldElement<F>]) -> Self {
        Self {
            signals,
            witness_slots,
        }
    }
}

mod arrays;
mod canonical;
mod family;
mod int_ops;
mod state;
mod step;

#[cfg(test)]
mod tests;

use family::check_family_compat;
use state::{Flow, State};
use step::step;

/// Run `prog` with the default instruction budget.
pub fn execute<F: FieldBackend>(
    prog: &Program,
    ctx: &mut ArtikContext<'_, F>,
) -> Result<(), ArtikError> {
    execute_with_budget(prog, ctx, DEFAULT_BUDGET)
}

/// Run `prog` and abort after `budget` instructions. Guards against
/// non-terminating loops in malicious or buggy bytecode.
pub fn execute_with_budget<F: FieldBackend>(
    prog: &Program,
    ctx: &mut ArtikContext<'_, F>,
    budget: u64,
) -> Result<(), ArtikError> {
    // Field family compat check — the bytecode declares one family and
    // the caller picks a backend; reject early if they do not match.
    check_family_compat::<F>(prog.header.family)?;

    let mut state = State::<F>::new(prog)?;

    let mut ran: u64 = 0;
    loop {
        if ran >= budget {
            return Err(ArtikError::BudgetExhausted { ran });
        }
        ran += 1;

        let (func_id, pc) = {
            let f = state.top()?;
            (f.func_id, f.pc)
        };
        let body = &prog.subprograms[func_id as usize].body;

        // A PC that falls off the end of a subprogram (including an
        // empty body) is a validator gap, not a panic — adversarial
        // bytecode could hit this by omitting the final `Return`.
        // Surface as `InvalidJumpTarget` so the caller sees a clean
        // error.
        if (pc as usize) >= body.len() {
            return Err(ArtikError::InvalidJumpTarget { target: pc });
        }
        let instr = &body[pc as usize];
        match step(instr, &mut state, ctx, prog)? {
            Flow::Next => state.top_mut()?.pc = pc + 1,
            Flow::JumpTo(idx) => state.top_mut()?.pc = idx,
            Flow::Call {
                func_id: callee,
                args,
                rets,
            } => {
                state.enter_call(prog, callee, &args, rets, pc)?;
            }
            Flow::Return { srcs } => {
                if state.do_return(&srcs)? {
                    return Ok(());
                }
            }
        }
    }
}
