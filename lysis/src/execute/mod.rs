//! Bytecode executor — register-based dispatch loop that emits IR
//! into an [`IrSink`].
//!
//! The current executor is a straight interpreter on the decoded
//! [`Program`]: every opcode dispatches through a single big `match`
//! and every emission goes through the sink. It is deliberately
//! naïve — no hash-consing, no optimization, no lazy evaluation —
//! the dispatch shape is designed so a future interning sink can
//! replace [`StubSink`] without touching this loop.
//!
//! ## Contract with the validator
//!
//! [`crate::bytecode::validate`] must have accepted the program
//! before [`execute`] runs; the executor relies on most structural
//! invariants (opcodes well-formed, const pool indices in range,
//! template ids defined) and only double-checks the few that depend
//! on runtime information:
//!
//! - **Rule 2** (family compat) — checked against
//!   `F::PRIME_ID` at entry via [`expected_family`].
//! - **Rule 5** (capture idx in range) — checked per-`LoadCapture`.
//! - **Rule 11 runtime backstop** — `max_call_depth` is re-checked
//!   at every `InstantiateTemplate` push.
//!
//! Any other structural error is a validator bug; the executor
//! surfaces it as [`LysisError::ReadUndefinedRegister`] or similar
//! so the program crashes loud rather than silently.

pub mod draining_sink;
pub mod frame;
pub mod interning_sink;
pub mod ir_sink;
pub mod stub_sink;

pub use draining_sink::ChunkDrainingSink;
pub use frame::{Frame, LoopState};
pub use interning_sink::InterningSink;
pub use ir_sink::IrSink;
pub use stub_sink::StubSink;

mod dispatch;
mod loops;
mod profile;
mod runtime;
mod step;
mod templates;

#[cfg(test)]
mod tests;

use memory::field::{FieldBackend, FieldElement, PrimeId};
use memory::FieldFamily;

use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::intern::NodeId;
use crate::program::Program;

use dispatch::dispatch;
use loops::advance_loops;
use profile::LysisExecProfile;
use runtime::pop_frame;
use step::Step;
use templates::{build_template_tables, root_body_range};

/// Shorthand for the `result` placeholder used in pure kinds passed
/// to [`IrSink::intern_pure`]. The sink chooses the canonical id;
/// the value here is arbitrary and deliberately the same across
/// call sites so the intent reads cleanly.
const PLACEHOLDER_ID: NodeId = NodeId::PLACEHOLDER;

/// The canonical family for a given `FieldBackend`. Mirrors Artik's
/// `check_family_compat` mapping.
pub fn expected_family<F: FieldBackend>() -> FieldFamily {
    match F::PRIME_ID {
        PrimeId::Bn254
        | PrimeId::Bls12_381
        | PrimeId::Grumpkin
        | PrimeId::Pallas
        | PrimeId::Vesta
        | PrimeId::Secp256r1
        | PrimeId::Bls12_377 => FieldFamily::BnLike256,
        PrimeId::Goldilocks => FieldFamily::Goldilocks64,
    }
}

/// Execute a validated program, producing emissions into `sink`.
///
/// `captures` are the root-level arguments (typically field constants
/// bound to `LoadCapture` opcodes). Emitting `LoadCapture idx` where
/// `idx >= captures.len()` is a runtime error (rule 5).
pub fn execute<F: FieldBackend, S: IrSink<F>>(
    program: &Program<F>,
    captures: &[FieldElement<F>],
    config: &LysisConfig,
    sink: &mut S,
) -> Result<(), LysisError> {
    // Rule 2: family compat at entry.
    let expected = expected_family::<F>();
    if program.header.family != expected {
        return Err(LysisError::FieldFamilyMismatch {
            declared: program.header.family,
            expected,
        });
    }

    let (template_lookup, template_body_ranges) = build_template_tables(program);

    // Determine the instruction range of the top-level (root) body:
    // every instruction whose offset is not inside any template body.
    let (root_start, root_end) = root_body_range(program);

    let mut frames: Vec<Frame> = vec![Frame {
        regs: vec![None; 256],
        pc: root_start,
        body_start_idx: root_start,
        body_end_idx: root_end,
        template_id: None,
        output_slots: Vec::new(),
        caller_output_regs: Vec::new(),
        caller_frame_idx: None,
        loop_stack: Vec::new(),
    }];

    // Program-global heap for spill opcodes (StoreHeap / LoadHeap).
    // Sized exactly to header.heap_size_hint so that the
    // heap-slot-bounds rule (slot < heap_size_hint) is enforced as a
    // bounds check. v1 streams arrive with heap_size_hint = 0 and
    // never emit heap opcodes; the empty Vec is the right shape.
    //
    // `vec![None; n]` not `with_capacity(n)`: StoreHeap writes via
    // direct index, so len() must include the addressable range up
    // front.
    let mut heap: Vec<Option<NodeId>> = vec![None; program.header.heap_size_hint as usize];

    let mut instructions_executed: u64 = 0;
    let mut exec_profile = LysisExecProfile::from_env(program);

    loop {
        // Instruction budget.
        instructions_executed += 1;
        if instructions_executed > config.instruction_budget {
            return Err(LysisError::BudgetExhausted {
                ran: instructions_executed,
                budget: config.instruction_budget,
            });
        }

        let frame_idx = frames.len() - 1;
        let frame = &mut frames[frame_idx];

        if frame.pc >= frame.body_end_idx {
            // Ran off the frame without Return/Halt — validator
            // should have caught this but surface it clearly.
            let last_offset = program
                .body
                .get(frame.pc.saturating_sub(1))
                .map(|i| i.offset)
                .unwrap_or(0);
            return Err(LysisError::UnreachableReturn {
                at_offset: last_offset,
            });
        }

        let instr = &program.body[frame.pc];
        if let Some(profile) = exec_profile.as_mut() {
            profile.record(instr, frame.template_id, instructions_executed);
            if profile.should_abort(instructions_executed) {
                profile.print(instructions_executed);
                return Err(LysisError::BudgetExhausted {
                    ran: instructions_executed,
                    budget: profile.abort_after.unwrap_or(instructions_executed),
                });
            }
        }
        let advance = dispatch(
            instr,
            frame_idx,
            &mut frames,
            program,
            captures,
            config,
            sink,
            &template_lookup,
            &template_body_ranges,
            &mut heap,
        )?;

        match advance {
            Step::Next => {
                frames[frame_idx].pc += 1;
            }
            Step::JumpToIndex(idx) => {
                frames[frame_idx].pc = idx;
            }
            Step::PushFrame(new_frame) => {
                // Advance the caller past the `InstantiateTemplate`
                // opcode before handing control to the callee. When
                // the callee `Return`s, `pop_frame` lands the caller
                // on the following instruction rather than re-running
                // the template call.
                frames[frame_idx].pc += 1;
                frames.push(new_frame);
            }
            Step::TailCall(mut new_frame) => {
                // The caller is in tail position with no outputs to
                // forward: replace it with the callee instead of
                // growing the stack. The callee inherits the caller's
                // return target so the eventual leaf `Return` unwinds
                // to the caller's caller (for the walker's split-chain
                // that is the root), keeping the chain O(1) in frames.
                let caller = frames.pop().expect("frame_idx valid implies a frame");
                new_frame.caller_frame_idx = caller.caller_frame_idx;
                new_frame.caller_output_regs = caller.caller_output_regs;
                new_frame.output_slots = vec![None; new_frame.caller_output_regs.len()];
                frames.push(new_frame);
            }
            Step::PopFrame => {
                pop_frame(&mut frames)?;
            }
            Step::Halt => {
                if let Some(profile) = exec_profile.as_ref() {
                    profile.print(instructions_executed);
                }
                return Ok(());
            }
        }
        // Check whether the current top frame just fell off the end
        // of an active LoopUnroll body; if so, iterate or pop.
        advance_loops(&mut frames, sink);
    }
}
