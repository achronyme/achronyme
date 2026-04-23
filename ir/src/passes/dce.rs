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

#[cfg(test)]
mod tests {
    use diagnostics::SpanRange;
    use ir_core::{Instruction, IrProgram, Visibility};
    use memory::FieldElement;

    use super::dead_code_elimination;

    #[test]
    fn var_spans_survive_dce() {
        // var_spans are keyed by SsaVar, not instruction index,
        // so they survive DCE which removes instructions via retain().
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let span = SpanRange::new(0, 10, 1, 1, 1, 10);
        p.set_span(v0, span.clone());

        // v1 is unused, will be eliminated by DCE
        let v1 = p.fresh_var();
        p.push(Instruction::Const {
            result: v1,
            value: FieldElement::from_u64(42),
        });

        // v2: non-tautological AssertEq (survives DCE)
        let v2 = p.fresh_var();
        let v3 = p.fresh_var();
        p.push(Instruction::Const {
            result: v3,
            value: FieldElement::from_u64(0),
        });
        p.push(Instruction::AssertEq {
            result: v2,
            lhs: v0,
            rhs: v3,
            message: None,
        });
        let span2 = SpanRange::new(20, 30, 2, 1, 2, 10);
        p.set_span(v2, span2.clone());

        dead_code_elimination(&mut p);

        // v1 (unused Const) is gone; Input + Const(0) + AssertEq remain.
        assert_eq!(p.instructions.len(), 3);
        assert_eq!(p.get_span(v0), Some(&span));
        assert_eq!(p.get_span(v2), Some(&span2));
    }
}
