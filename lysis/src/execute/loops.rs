use memory::field::{FieldBackend, FieldElement};

use crate::error::LysisError;
use crate::intern::InstructionKind;
use crate::program::Program;

use super::frame::{Frame, LoopState};
use super::ir_sink::IrSink;
use super::step::Step;
use super::templates::{exact_offset_idx, lower_bound_offset_idx};
use super::PLACEHOLDER_ID;

/// Byte size of a `LoopUnroll` opcode (1 tag + 1 reg + 4 start + 4
/// end + 2 body_len). Matches the encoding in `bytecode::encoding`.
const LOOP_UNROLL_OPCODE_BYTES: u32 = 12;

/// Handle the `LoopUnroll` opcode: bind iter_var to
/// `Const(start)`, push a [`LoopState`], and jump into the body.
/// If the loop range is empty, skip past the body entirely.
#[allow(clippy::too_many_arguments)]
pub(super) fn enter_loop_unroll<F: FieldBackend, S: IrSink<F>>(
    offset: u32,
    frame_idx: usize,
    frames: &mut [Frame],
    iter_var: u8,
    start: u32,
    end: u32,
    body_len: u16,
    program: &Program<F>,
    sink: &mut S,
) -> Result<Step, LysisError> {
    let body_byte_start = offset.saturating_add(LOOP_UNROLL_OPCODE_BYTES);
    let body_byte_end = body_byte_start.saturating_add(u32::from(body_len));

    let body_start_idx =
        exact_offset_idx(program, body_byte_start).ok_or(LysisError::ValidationFailed {
            rule: 0,
            location: offset,
            detail: "LoopUnroll body start does not align to an opcode boundary",
        })?;

    // body_end_idx = smallest instruction index whose offset is
    // >= body_byte_end. If no such index exists we're at the end of
    // the program body.
    let body_end_idx = lower_bound_offset_idx(program, body_byte_end);

    if start >= end {
        // Empty loop — skip straight past the body.
        return Ok(Step::JumpToIndex(body_end_idx));
    }

    // Emit Const(start) into iter_var.
    let iter_fe = u32_as_field::<F>(start);
    let id = sink.intern_pure(InstructionKind::Const {
        result: PLACEHOLDER_ID,
        value: iter_fe,
    });
    frames[frame_idx].write(iter_var, id);

    frames[frame_idx].loop_stack.push(LoopState {
        iter_reg: iter_var,
        start,
        end,
        current: start,
        body_start_idx,
        body_end_idx,
    });

    Ok(Step::JumpToIndex(body_start_idx))
}

/// After the main loop updates `pc`, check whether the current top
/// frame has fallen off the end of an active `LoopUnroll` body. If
/// so, either advance the iteration counter and jump back, or pop
/// the loop and fall through.
pub(super) fn advance_loops<F: FieldBackend, S: IrSink<F>>(frames: &mut [Frame], sink: &mut S) {
    if frames.is_empty() {
        return;
    }
    let top = frames.len() - 1;
    while let Some(ls) = frames[top].loop_stack.last().copied() {
        if frames[top].pc < ls.body_end_idx {
            break;
        }
        // At or past the loop body boundary.
        let next_current = ls.current.saturating_add(1);
        if next_current < ls.end {
            // New iteration: rebind iter_var + jump back.
            let fe = u32_as_field::<F>(next_current);
            let id = sink.intern_pure(InstructionKind::Const {
                result: PLACEHOLDER_ID,
                value: fe,
            });
            let frame = &mut frames[top];
            frame.write(ls.iter_reg, id);
            frame.pc = ls.body_start_idx;
            if let Some(last) = frame.loop_stack.last_mut() {
                last.current = next_current;
            }
            // After jumping back we know pc < body_end (enter_loop_unroll
            // rejects empty ranges, so body_start < body_end), so the
            // next `while let` check will see pc < body_end and break.
            break;
        } else {
            // Last iteration done — pop and continue to check outer
            // loops (if any).
            frames[top].loop_stack.pop();
        }
    }
}

/// Convert a `u32` iteration counter to a `FieldElement<F>`. The
/// low-limb-only encoding is correct for any `u32` because field
/// primes are all ≥ 2^32 in practice (Goldilocks is the smallest at
/// 2^64 - 2^32 + 1).
fn u32_as_field<F: FieldBackend>(n: u32) -> FieldElement<F> {
    FieldElement::from_canonical([u64::from(n), 0, 0, 0])
}
