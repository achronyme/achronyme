use std::collections::HashSet;

use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 7 — every InstantiateTemplate references a previously
// DefineTemplate-d id.
// ---------------------------------------------------------------------

pub(super) fn check_templates_defined<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    let known: HashSet<u16> = program.templates.iter().map(|t| t.id).collect();
    for instr in &program.body {
        if let Opcode::InstantiateTemplate { template_id, .. } = &instr.opcode {
            if !known.contains(template_id) {
                return Err(LysisError::UndefinedTemplate {
                    at_offset: instr.offset,
                    template_id: *template_id,
                });
            }
        }
        if let Opcode::LoopRolled {
            body_template_id, ..
        }
        | Opcode::LoopRange {
            body_template_id, ..
        } = &instr.opcode
        {
            if !known.contains(body_template_id) {
                return Err(LysisError::UndefinedTemplate {
                    at_offset: instr.offset,
                    template_id: *body_template_id,
                });
            }
        }
    }
    Ok(())
}
