use std::collections::HashSet;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Dead code elimination pass.
///
/// Iterates until fixpoint. Each round collects used variables from all
/// retained instructions, then removes instructions whose result is unused
/// and that are safe to eliminate.
///
/// Side-effect instructions (`AssertEq`, `Assert`, `Input`, `RangeCheck`)
/// are never eliminated, except for tautological `AssertEq(x, x)` which
/// carry zero information and are always safe to remove.
pub fn dead_code_elimination<F: FieldBackend>(program: &mut IrProgram<F>) {
    // Pre-pass: eliminate tautological AssertEq(x, x).
    // These arise during Circom component inlining when an output signal
    // is wired to an input that already refers to the same SSA variable.
    program.retain_instructions(
        |inst| !matches!(inst, Instruction::AssertEq { lhs, rhs, .. } if lhs == rhs),
    );

    loop {
        let before = program.len();

        // 1. Collect all used variables from current instructions
        let mut used: HashSet<SsaVar> = HashSet::new();
        for inst in program.iter() {
            for op in inst.operands() {
                used.insert(op);
            }
        }

        // 2. Remove instructions whose result is unused and are safe to eliminate
        program.retain_instructions(|inst| {
            // Never eliminate side-effect instructions
            if inst.has_side_effects() {
                return true;
            }

            let result = inst.result_var();
            used.contains(&result)
        });

        // Fixpoint reached — no more instructions removed
        if program.len() == before {
            break;
        }
    }
}
