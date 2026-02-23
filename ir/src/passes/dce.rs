use std::collections::HashSet;

use crate::types::{IrProgram, SsaVar};

/// Dead code elimination pass.
///
/// Iterates until fixpoint. Each round collects used variables from all
/// retained instructions, then removes instructions whose result is unused
/// and that are safe to eliminate.
///
/// Side-effect instructions (`AssertEq`, `Assert`, `Input`, `RangeCheck`)
/// are never eliminated. All other instructions are eliminated if their
/// result variable is unused by any retained instruction.
pub fn dead_code_elimination(program: &mut IrProgram) {
    loop {
        let before = program.instructions.len();

        // 1. Collect all used variables from current instructions
        let mut used: HashSet<SsaVar> = HashSet::new();
        for inst in &program.instructions {
            for op in inst.operands() {
                used.insert(op);
            }
        }

        // 2. Remove instructions whose result is unused and are safe to eliminate
        program.instructions.retain(|inst| {
            // Never eliminate side-effect instructions
            if inst.has_side_effects() {
                return true;
            }

            let result = inst.result_var();
            used.contains(&result)
        });

        // Fixpoint reached — no more instructions removed
        if program.instructions.len() == before {
            break;
        }
    }
}
