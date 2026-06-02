use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

use super::dataflow::hosting_template;

// ---------------------------------------------------------------------
// Rule 10 — `Return` reachable from every code path.
// Current approximation: each body must end in a terminator.
// ---------------------------------------------------------------------

pub(super) fn check_reachable_return<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    // Check the top-level body.
    if let Some(last) = program
        .body
        .iter()
        .rfind(|i| hosting_template(program, i.offset).is_none())
    {
        if !is_terminator(&last.opcode) {
            return Err(LysisError::UnreachableReturn {
                at_offset: last.offset,
            });
        }
    }

    // Check each template body.
    for t in &program.templates {
        let last = program.body.iter().rfind(|i| {
            i.offset >= t.body_offset && i.offset < t.body_offset.saturating_add(t.body_len)
        });
        match last {
            None => {
                // Empty template body — technically unreachable on
                // call. Reject: every DefineTemplate must have at
                // least a Return.
                return Err(LysisError::UnreachableReturn {
                    at_offset: t.body_offset,
                });
            }
            Some(i) if !is_terminator(&i.opcode) => {
                return Err(LysisError::UnreachableReturn {
                    at_offset: i.offset,
                });
            }
            _ => {}
        }
    }

    Ok(())
}

fn is_terminator(op: &Opcode) -> bool {
    matches!(
        op,
        Opcode::Return | Opcode::Halt | Opcode::Trap { .. } | Opcode::Jump { .. }
    )
}
