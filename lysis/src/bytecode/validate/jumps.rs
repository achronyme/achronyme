use std::collections::HashSet;

use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 6 — `Jump`/`JumpIf` targets land on opcode boundaries inside
// the same template body (no cross-template jumps).
// ---------------------------------------------------------------------

pub(super) fn check_jump_targets<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let offsets: HashSet<u32> = program.body.iter().map(|i| i.offset).collect();

    for instr in &program.body {
        let rel = match &instr.opcode {
            Opcode::Jump { offset } | Opcode::JumpIf { offset, .. } => *offset as i64,
            _ => continue,
        };

        // Jump is relative to the end of the current opcode per RFC
        // (`pc += offset`). We can compute the expected
        // absolute offset from the current instruction's offset plus
        // its own encoded length. The current check simply requires
        // the target to land on *some* opcode boundary inside the
        // same template region.
        let target = instr.offset as i64 + rel;
        if target < 0 {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
        let target_u32 = target as u32;
        if !offsets.contains(&target_u32) {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
        if !same_template_body(program, instr.offset, target_u32) {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
    }
    Ok(())
}

fn same_template_body<F: FieldBackend>(program: &Program<F>, src: u32, dst: u32) -> bool {
    let host = program.templates.iter().find(|t| {
        let end = t.body_offset.saturating_add(t.body_len);
        src >= t.body_offset && src < end
    });
    match host {
        Some(t) => {
            let end = t.body_offset.saturating_add(t.body_len);
            dst >= t.body_offset && dst < end
        }
        None => {
            // src lives in top-level body; dst must also be top-level.
            !program.templates.iter().any(|t| {
                let end = t.body_offset.saturating_add(t.body_len);
                dst >= t.body_offset && dst < end
            })
        }
    }
}
