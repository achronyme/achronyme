//! Per-pass SSA-integrity validator.
//!
//! Walks the program in order and verifies that every operand reference
//! resolves to an `SsaVar` defined by a prior instruction (the SSA
//! topological invariant the R1CS compiler assumes).
//!
//! Disabled by default. Set `ACHRONYME_VALIDATE_IR_PASSES=1` to enable;
//! the validator then panics with the offending pass name, instruction
//! index, the dangling `SsaVar`, and (when a `before` snapshot is
//! provided) the original defining instruction. Used to bisect which
//! pass inside `optimize()` produces malformed IR.

use std::collections::HashSet;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Returns true iff the `ACHRONYME_VALIDATE_IR_PASSES` env var is set.
///
/// Re-read per call (no caching) so tests can toggle the flag at
/// runtime without the first read winning permanently. The cost
/// is one syscall per optimize-pass boundary — negligible against
/// the cost of running the validator itself when enabled, and
/// invisible (early-return) when disabled.
pub fn validation_enabled() -> bool {
    std::env::var_os("ACHRONYME_VALIDATE_IR_PASSES").is_some()
}

/// Assert that every operand reference in `program` is dominated by a
/// defining instruction earlier in the program. No-op when the
/// `ACHRONYME_VALIDATE_IR_PASSES` env var is unset.
pub fn assert_no_dangling_ssa_vars<F: FieldBackend>(
    program: &IrProgram<F>,
    pass_name: &'static str,
) {
    assert_no_dangling_ssa_vars_with_before::<F>(program, None, pass_name);
}

/// Same as [`assert_no_dangling_ssa_vars`], but also takes a snapshot of
/// the instruction stream as it looked *before* the pass ran. When a
/// dangling reference is found, the snapshot is searched for the
/// defining instruction so the panic message includes both the
/// before-state (where it lived) and the after-state (where it's now
/// missing). The snapshot is ignored when validation is disabled.
pub fn assert_no_dangling_ssa_vars_with_before<F: FieldBackend>(
    program: &IrProgram<F>,
    before: Option<&[Instruction<F>]>,
    pass_name: &'static str,
) {
    if !validation_enabled() {
        return;
    }

    let mut defined: HashSet<SsaVar> = HashSet::with_capacity(program.len());
    for (idx, inst) in program.instructions.iter().enumerate() {
        for op in inst.operands() {
            if !defined.contains(&op) {
                report_dangling(program, before, pass_name, idx, op);
            }
        }
        defined.insert(inst.result_var());
        for extra in inst.extra_result_vars() {
            defined.insert(*extra);
        }
    }
}

/// Build a panic message with diagnostic context for a dangling
/// SsaVar. Prints instruction windows in both the post-pass program
/// and (if available) the pre-pass snapshot.
fn report_dangling<F: FieldBackend>(
    program: &IrProgram<F>,
    before: Option<&[Instruction<F>]>,
    pass_name: &'static str,
    use_idx: usize,
    var: SsaVar,
) -> ! {
    let inst = &program.instructions[use_idx];

    let mut msg = format!(
        "[{pass_name}] dangling SsaVar({}): used by instruction #{use_idx} ({inst}), \
         but not defined by any prior instruction in the post-pass program",
        var.0,
    );

    msg.push_str("\n  --- post-pass window around use ---\n");
    push_window(&mut msg, &program.instructions, use_idx, 3);

    let post_defs: Vec<usize> = program
        .instructions
        .iter()
        .enumerate()
        .filter_map(|(i, inst)| {
            if inst.result_var() == var || inst.extra_result_vars().contains(&var) {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    if post_defs.is_empty() {
        msg.push_str(&format!(
            "\n  --- post-pass: SsaVar({}) is NOT defined anywhere in the program ---",
            var.0,
        ));
    } else {
        msg.push_str(&format!(
            "\n  --- post-pass: SsaVar({}) is defined at indices {:?} (ALL after the use!) ---",
            var.0, post_defs,
        ));
    }

    if let Some(before_slice) = before {
        let pre_defs: Vec<usize> = before_slice
            .iter()
            .enumerate()
            .filter_map(|(i, inst)| {
                if inst.result_var() == var || inst.extra_result_vars().contains(&var) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        if pre_defs.is_empty() {
            msg.push_str(&format!(
                "\n  --- pre-pass: SsaVar({}) was NOT defined either; the bug is upstream of {pass_name} ---",
                var.0,
            ));
        } else {
            msg.push_str(&format!(
                "\n  --- pre-pass: SsaVar({}) was defined at indices {:?} ---\n",
                var.0, pre_defs,
            ));
            push_window(&mut msg, before_slice, pre_defs[0], 3);

            // Probe for additional definitions of the result_var of the
            // pre-pass defining instruction (helps spot alias-style
            // definitions where result == operand).
            let pre_def_inst = &before_slice[pre_defs[0]];
            let pre_result = pre_def_inst.result_var();
            let pre_result_defs: Vec<usize> = before_slice
                .iter()
                .enumerate()
                .filter_map(|(i, ins)| {
                    if ins.result_var() == pre_result {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            msg.push_str(&format!(
                "  (pre-pass: SsaVar({}) [the result_var of the def] had {} definers at indices {:?})\n",
                pre_result.0,
                pre_result_defs.len(),
                pre_result_defs,
            ));
            for op in pre_def_inst.operands() {
                let occurrences: Vec<usize> = before_slice
                    .iter()
                    .enumerate()
                    .filter_map(|(i, ins)| {
                        if ins.result_var() == op || ins.extra_result_vars().contains(&op) {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .collect();
                msg.push_str(&format!(
                    "  (pre-pass: pre-def operand SsaVar({}) had {} definers at indices {:?})\n",
                    op.0,
                    occurrences.len(),
                    occurrences,
                ));
            }
            // Same probe in post-pass:
            let post_pre_result_defs: Vec<usize> = program
                .instructions
                .iter()
                .enumerate()
                .filter_map(|(i, ins)| {
                    if ins.result_var() == pre_result {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            msg.push_str(&format!(
                "  (post-pass: SsaVar({}) had {} definers at indices {:?})\n",
                pre_result.0,
                post_pre_result_defs.len(),
                post_pre_result_defs,
            ));
        }
    } else {
        msg.push_str("\n  (no pre-pass snapshot supplied)");
    }

    panic!("{msg}");
}

fn push_window<F: FieldBackend>(
    msg: &mut String,
    insts: &[Instruction<F>],
    centre: usize,
    radius: usize,
) {
    let start = centre.saturating_sub(radius);
    let end = (centre + radius + 1).min(insts.len());
    for (i, inst) in insts.iter().enumerate().take(end).skip(start) {
        let marker = if i == centre { ">>" } else { "  " };
        msg.push_str(&format!("  {marker} #{i}: {inst}\n"));
    }
}

#[cfg(test)]
mod tests {
    use ir_core::{Instruction, IrProgram, SsaVar, Visibility};
    use memory::FieldElement;

    use super::*;

    fn enable_validation() {
        unsafe { std::env::set_var("ACHRONYME_VALIDATE_IR_PASSES", "1") };
    }

    #[test]
    fn well_formed_program_passes() {
        enable_validation();
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        let v2 = p.fresh_var();
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Const {
            result: v1,
            value: FieldElement::from_u64(2),
        });
        p.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        assert_no_dangling_ssa_vars(&p, "test");
    }

    #[test]
    #[should_panic(expected = "dangling SsaVar(99)")]
    fn dangling_operand_panics() {
        enable_validation();
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Mul {
            result: v1,
            lhs: v0,
            rhs: SsaVar(99),
        });
        assert_no_dangling_ssa_vars(&p, "test");
    }

    #[test]
    #[should_panic(expected = "dangling SsaVar(0)")]
    fn forward_reference_panics() {
        enable_validation();
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        p.push(Instruction::Mul {
            result: v1,
            lhs: v0,
            rhs: v0,
        });
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        assert_no_dangling_ssa_vars(&p, "test");
    }

    #[test]
    fn decompose_extra_results_are_defined() {
        enable_validation();
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        let b0 = p.fresh_var();
        let b1 = p.fresh_var();
        let v_use = p.fresh_var();
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Decompose {
            result: v1,
            bit_results: vec![b0, b1],
            operand: v0,
            num_bits: 2,
        });
        p.push(Instruction::Add {
            result: v_use,
            lhs: b0,
            rhs: b1,
        });
        assert_no_dangling_ssa_vars(&p, "test");
    }

    #[test]
    #[should_panic(expected = "pre-pass: SsaVar(7) was defined at indices [1]")]
    fn before_snapshot_locates_origin() {
        enable_validation();
        // before: [Input %0, Const %7, Mul(%0, %7)]
        // after:  [Input %0, Mul(%0, %7)] — Const removed, ref dangles
        let v0 = SsaVar(0);
        let v7 = SsaVar(7);
        let v_use = SsaVar(8);
        let before = vec![
            Instruction::Input {
                result: v0,
                name: "x".into(),
                visibility: Visibility::Public,
            },
            Instruction::Const {
                result: v7,
                value: FieldElement::from_u64(42),
            },
            Instruction::Mul {
                result: v_use,
                lhs: v0,
                rhs: v7,
            },
        ];
        let mut after: IrProgram = IrProgram::new();
        after.next_var = 9;
        after.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        after.push(Instruction::Mul {
            result: v_use,
            lhs: v0,
            rhs: v7,
        });
        assert_no_dangling_ssa_vars_with_before(&after, Some(&before), "test");
    }
}
