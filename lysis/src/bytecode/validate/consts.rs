use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 4 — `LoadConst idx < const_pool_len`
// and the related `EmitWitnessCall bytecode_const_idx`.
// ---------------------------------------------------------------------

pub(super) fn check_const_bounds<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let pool_len = program.const_pool.len() as u32;
    for instr in &program.body {
        match &instr.opcode {
            Opcode::LoadConst { idx, .. } => {
                if *idx >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *idx,
                        len: pool_len,
                    });
                }
            }
            Opcode::LoadInput { name_idx, .. } => {
                if *name_idx >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *name_idx,
                        len: pool_len,
                    });
                }
            }
            Opcode::EmitAssertEqMsg { msg_idx, .. } => {
                if *msg_idx >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *msg_idx,
                        len: pool_len,
                    });
                }
            }
            Opcode::EmitWitnessCall {
                bytecode_const_idx, ..
            } if *bytecode_const_idx >= pool_len => {
                return Err(LysisError::ConstIdxOutOfRange {
                    at_offset: instr.offset,
                    idx: *bytecode_const_idx,
                    len: pool_len,
                });
            }
            _ => {}
        }
    }
    Ok(())
}
