use memory::field::FieldBackend;

use crate::error::LysisError;
use crate::intern::NodeId;
use crate::program::Program;

use super::frame::Frame;
use super::templates::exact_offset_idx;

pub(super) fn read_reg(frame: &Frame, reg: u8, at_offset: u32) -> Result<NodeId, LysisError> {
    frame
        .read(reg)
        .ok_or(LysisError::ReadUndefinedRegister { reg, at_offset })
}

pub(super) fn read_binary(
    frame: &Frame,
    lhs: u8,
    rhs: u8,
    at_offset: u32,
) -> Result<(NodeId, NodeId), LysisError> {
    Ok((
        read_reg(frame, lhs, at_offset)?,
        read_reg(frame, rhs, at_offset)?,
    ))
}

pub(super) fn resolve_jump<F: FieldBackend>(
    target: i64,
    program: &Program<F>,
) -> Result<usize, LysisError> {
    if target < 0 || target > u32::MAX as i64 {
        return Err(LysisError::BadJumpTarget {
            at_offset: 0,
            target_offset: target,
        });
    }
    exact_offset_idx(program, target as u32).ok_or(LysisError::BadJumpTarget {
        at_offset: 0,
        target_offset: target,
    })
}

pub(super) fn pop_frame(frames: &mut Vec<Frame>) -> Result<(), LysisError> {
    if frames.len() <= 1 {
        return Err(LysisError::UnreachableReturn { at_offset: 0 });
    }
    let popped = frames.pop().expect("stack len > 1 guarantees a frame");
    let caller_idx = popped
        .caller_frame_idx
        .expect("non-root frames carry caller idx");
    let caller = &mut frames[caller_idx];
    for (out_reg, slot) in popped
        .caller_output_regs
        .iter()
        .zip(popped.output_slots.iter())
    {
        if let Some(id) = slot {
            if (*out_reg as usize) < caller.regs.len() {
                caller.regs[*out_reg as usize] = Some(*id);
            }
        }
    }
    Ok(())
}
