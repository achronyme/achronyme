use std::collections::HashSet;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Dead code elimination pass.
///
/// Iterates until fixpoint. Each round collects used variables from all
/// retained instructions, then removes instructions whose result is unused
/// and that are safe to eliminate.
///
/// Conservative: `Mul`, `Div`, `Mux`, `PoseidonHash` are NOT eliminated even
/// if unused, because they generate constraints in the R1CS backend.
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

            // Conservative: keep instructions that generate constraints
            match inst {
                Instruction::Mul { .. }
                | Instruction::Div { .. }
                | Instruction::Mux { .. }
                | Instruction::PoseidonHash { .. }
                | Instruction::RangeCheck { .. }
                | Instruction::Not { .. }
                | Instruction::And { .. }
                | Instruction::Or { .. }
                | Instruction::IsEq { .. }
                | Instruction::IsNeq { .. }
                | Instruction::IsLt { .. }
                | Instruction::IsLe { .. } => return true,
                _ => {}
            }

            // Safe to eliminate: Const, Add, Sub, Neg
            let result = inst.result_var();
            used.contains(&result)
        });

        // Fixpoint reached — no more instructions removed
        if program.instructions.len() == before {
            break;
        }
    }
}
