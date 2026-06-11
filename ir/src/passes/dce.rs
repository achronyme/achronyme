use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

const NO_DEF: usize = usize::MAX;

/// Dead code elimination pass.
///
/// Use-count worklist: count every operand occurrence, seed with pure
/// instructions whose result is unreferenced, and cascade — removing an
/// instruction decrements its operands' counts, which can newly orphan
/// their defining instructions. This computes the same fixpoint as a
/// round-based rescan (a removal only ever *enables* further removals),
/// in one pass plus a worklist instead of O(rounds) full rescans.
///
/// Side-effect instructions (`AssertEq`, `Assert`, `Input`, `RangeCheck`,
/// `Decompose`, `WitnessCall`) are never eliminated, except for
/// tautological `AssertEq(x, x)` which carry zero information and are
/// always safe to remove.
pub fn dead_code_elimination<F: FieldBackend>(program: &mut IrProgram<F>) {
    // Pre-pass: eliminate tautological AssertEq(x, x).
    // These arise during Circom component inlining when an output signal
    // is wired to an input that already refers to the same SSA variable.
    // Use counts are taken AFTER this retain so the tautological asserts'
    // operands don't keep their producers alive.
    program.retain_instructions(
        |inst| !matches!(inst, Instruction::AssertEq { lhs, rhs, .. } if lhs == rhs),
    );

    let n = program.len();

    // One pass: per-variable use counts (operand multiset, verbatim —
    // self-references and duplicates included) + defining-instruction
    // index. The worklist relies on each variable having at most one
    // definition; degenerate duplicate-def input falls back to the
    // round-based scan, which removes all definitions of an orphaned
    // variable together.
    let mut counts: Vec<u32> = vec![0; program.next_var as usize];
    let mut def: Vec<usize> = vec![NO_DEF; program.next_var as usize];
    for (i, inst) in program.instructions.iter().enumerate() {
        inst.for_each_operand(|v| {
            let i = v.0 as usize;
            if i >= counts.len() {
                counts.resize(i + 1, 0);
            }
            counts[i] += 1;
        });
        let r = inst.result_var().0 as usize;
        if r >= def.len() {
            def.resize(r + 1, NO_DEF);
        }
        if def[r] != NO_DEF {
            return fixpoint_dce(program);
        }
        def[r] = i;
    }
    if counts.len() < def.len() {
        counts.resize(def.len(), 0);
    }

    // Seed: pure instructions whose result no retained instruction reads.
    let mut dead = vec![false; n];
    let mut work: Vec<usize> = Vec::new();
    for (i, inst) in program.instructions.iter().enumerate() {
        if !inst.has_side_effects() && counts[inst.result_var().0 as usize] == 0 {
            dead[i] = true;
            work.push(i);
        }
    }

    // Cascade. The operand buffer is reused across iterations.
    let mut ops: Vec<SsaVar> = Vec::new();
    while let Some(i) = work.pop() {
        ops.clear();
        program.instructions[i].for_each_operand(|v| ops.push(v));
        for &v in &ops {
            let c = &mut counts[v.0 as usize];
            *c -= 1;
            if *c == 0 {
                let j = def[v.0 as usize];
                if j != NO_DEF && !dead[j] && !program.instructions[j].has_side_effects() {
                    dead[j] = true;
                    work.push(j);
                }
            }
        }
    }

    // Single order-preserving sweep.
    let mut k = 0;
    program.retain_instructions(|_| {
        let keep = !dead[k];
        k += 1;
        keep
    });
}

/// Round-based fallback for degenerate (non-SSA) input where a variable
/// has more than one defining instruction. Each round collects used
/// variables from all retained instructions, then removes instructions
/// whose result is unused and that are safe to eliminate, until fixpoint.
fn fixpoint_dce<F: FieldBackend>(program: &mut IrProgram<F>) {
    use std::collections::HashSet;
    loop {
        let before = program.len();

        let mut used: HashSet<SsaVar> = HashSet::new();
        for inst in program.iter() {
            inst.for_each_operand(|v| {
                used.insert(v);
            });
        }

        program.retain_instructions(|inst| {
            if inst.has_side_effects() {
                return true;
            }
            used.contains(&inst.result_var())
        });

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

    #[test]
    fn cascade_removes_whole_dead_chain() {
        // a (Input, kept) <- b = Add(a, a) <- c = Neg(b) <- d = Neg(c),
        // d unused: the entire pure chain dies in one call.
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var();
        p.push(Instruction::Input {
            result: a,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let b = p.fresh_var();
        p.push(Instruction::Add {
            result: b,
            lhs: a,
            rhs: a,
        });
        let c = p.fresh_var();
        p.push(Instruction::Neg {
            result: c,
            operand: b,
        });
        let d = p.fresh_var();
        p.push(Instruction::Neg {
            result: d,
            operand: c,
        });

        dead_code_elimination(&mut p);

        assert_eq!(p.instructions.len(), 1);
        assert!(matches!(p.instructions[0], Instruction::Input { .. }));
    }

    #[test]
    fn self_reference_with_no_other_use_is_kept() {
        // Degenerate v = Add(v, v): the operand multiset keeps the use
        // count nonzero, so the instruction survives — matching the
        // round-based scan, where `used` always contains v.
        let mut p: IrProgram = IrProgram::new();
        let v = p.fresh_var();
        p.push(Instruction::Add {
            result: v,
            lhs: v,
            rhs: v,
        });

        dead_code_elimination(&mut p);

        assert_eq!(p.instructions.len(), 1);
    }

    #[test]
    fn chain_feeding_only_tautological_assert_is_removed() {
        // AssertEq(b, b) is tautological; with it gone, b's producer
        // (and a's, transitively) must die too — counts are taken after
        // the tautological pre-pass.
        let mut p: IrProgram = IrProgram::new();
        let x = p.fresh_var();
        p.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let a = p.fresh_var();
        p.push(Instruction::Neg {
            result: a,
            operand: x,
        });
        let b = p.fresh_var();
        p.push(Instruction::Mul {
            result: b,
            lhs: a,
            rhs: a,
        });
        let t = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: t,
            lhs: b,
            rhs: b,
            message: None,
        });

        dead_code_elimination(&mut p);

        assert_eq!(p.instructions.len(), 1);
        assert!(matches!(p.instructions[0], Instruction::Input { .. }));
    }

    #[test]
    fn duplicate_definitions_fall_back_and_both_die() {
        // Non-SSA degenerate input: two pure definitions of the same
        // variable, both unreferenced. The round-based fallback removes
        // both, exactly as a rescan-until-fixpoint does.
        let mut p: IrProgram = IrProgram::new();
        let keep = p.fresh_var();
        p.push(Instruction::Input {
            result: keep,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v = p.fresh_var();
        p.push(Instruction::Const {
            result: v,
            value: FieldElement::from_u64(1),
        });
        p.push(Instruction::Const {
            result: v,
            value: FieldElement::from_u64(2),
        });

        dead_code_elimination(&mut p);

        assert_eq!(p.instructions.len(), 1);
        assert!(matches!(p.instructions[0], Instruction::Input { .. }));
    }
}
