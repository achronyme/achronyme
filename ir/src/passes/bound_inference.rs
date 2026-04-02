//! Bound inference pass: rewrites unbounded IsLt/IsLe to IsLtBounded/IsLeBounded
//! when both operands have proven bitwidth bounds from prior RangeCheck instructions.
//!
//! This is the core of the D7 optimization. Without bounds, IsLt uses full 252-bit
//! decomposition (~761 constraints). With bounds, IsLtBounded uses n+1 bit decomposition
//! (~n+3 constraints, e.g. ~67 for 64-bit — matching Circom's LessThan(64)).
//!
//! Security model: safe-by-default. If either operand lacks a proven bound, the
//! instruction remains as unbounded IsLt/IsLe (252-bit fallback). No under-constrained
//! circuits can result from this optimization.

use std::collections::HashMap;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Result of the bound inference pass.
pub struct BoundInferenceResult {
    /// Number of IsLt/IsLe rewritten to bounded variants.
    pub rewritten: usize,
    /// SSA variables of comparisons that remained unbounded (~761 constraints each).
    /// Each entry is (result_var, lhs_var, rhs_var).
    pub unbounded: Vec<(SsaVar, SsaVar, SsaVar)>,
}

/// Run bound inference on the IR program.
///
/// Scans for RangeCheck instructions to build a bounds map, then rewrites
/// IsLt → IsLtBounded and IsLe → IsLeBounded when both operands have bounds.
pub fn bound_inference<F: FieldBackend>(program: &mut IrProgram<F>) -> BoundInferenceResult {
    // Phase 1: collect proven bounds from RangeCheck instructions.
    // RangeCheck { result, operand, bits } proves that `operand` fits in `bits` bits.
    // We track the tightest (smallest) bound per variable.
    let mut bounds: HashMap<SsaVar, u32> = HashMap::new();

    for inst in &program.instructions {
        if let Instruction::RangeCheck { operand, bits, .. } = inst {
            let entry = bounds.entry(*operand).or_insert(*bits);
            // Keep the tightest bound
            if *bits < *entry {
                *entry = *bits;
            }
        }
    }

    if bounds.is_empty() {
        // No range_checks at all — collect all IsLt/IsLe as unbounded
        let mut unbounded = Vec::new();
        for inst in &program.instructions {
            match inst {
                Instruction::IsLt { result, lhs, rhs } | Instruction::IsLe { result, lhs, rhs } => {
                    unbounded.push((*result, *lhs, *rhs));
                }
                _ => {}
            }
        }
        return BoundInferenceResult {
            rewritten: 0,
            unbounded,
        };
    }

    // Phase 2: rewrite IsLt/IsLe to bounded variants when both operands have bounds.
    let mut rewritten = 0;
    let mut unbounded = Vec::new();

    for inst in &mut program.instructions {
        match inst {
            Instruction::IsLt { result, lhs, rhs } => {
                if let (Some(&ba), Some(&bb)) = (bounds.get(lhs), bounds.get(rhs)) {
                    let bitwidth = ba.max(bb);
                    *inst = Instruction::IsLtBounded {
                        result: *result,
                        lhs: *lhs,
                        rhs: *rhs,
                        bitwidth,
                    };
                    rewritten += 1;
                } else {
                    unbounded.push((*result, *lhs, *rhs));
                }
            }
            Instruction::IsLe { result, lhs, rhs } => {
                if let (Some(&ba), Some(&bb)) = (bounds.get(lhs), bounds.get(rhs)) {
                    let bitwidth = ba.max(bb);
                    *inst = Instruction::IsLeBounded {
                        result: *result,
                        lhs: *lhs,
                        rhs: *rhs,
                        bitwidth,
                    };
                    rewritten += 1;
                } else {
                    unbounded.push((*result, *lhs, *rhs));
                }
            }
            _ => {}
        }
    }

    BoundInferenceResult {
        rewritten,
        unbounded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

    fn make_program_with_rangecheck_and_islt() -> IrProgram {
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var(); // %0
        let b = p.fresh_var(); // %1
        let ra = p.fresh_var(); // %2
        let rb = p.fresh_var(); // %3
        let lt = p.fresh_var(); // %4

        p.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::RangeCheck {
            result: ra,
            operand: a,
            bits: 64,
        });
        p.push(Instruction::RangeCheck {
            result: rb,
            operand: b,
            bits: 64,
        });
        p.push(Instruction::IsLt {
            result: lt,
            lhs: a,
            rhs: b,
        });
        p
    }

    #[test]
    fn rewrites_islt_when_both_bounded() {
        let mut p = make_program_with_rangecheck_and_islt();
        let result = bound_inference(&mut p);
        assert_eq!(result.rewritten, 1);
        match &p.instructions[4] {
            Instruction::IsLtBounded {
                bitwidth, lhs, rhs, ..
            } => {
                assert_eq!(*bitwidth, 64);
                assert_eq!(*lhs, SsaVar(0));
                assert_eq!(*rhs, SsaVar(1));
            }
            other => panic!("expected IsLtBounded, got {other:?}"),
        }
    }

    #[test]
    fn no_rewrite_when_one_unbounded() {
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let ra = p.fresh_var();
        let lt = p.fresh_var();

        p.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        // Only a has range_check, not b
        p.push(Instruction::RangeCheck {
            result: ra,
            operand: a,
            bits: 32,
        });
        p.push(Instruction::IsLt {
            result: lt,
            lhs: a,
            rhs: b,
        });

        let result = bound_inference(&mut p);
        assert_eq!(result.rewritten, 0);
        assert!(matches!(p.instructions[3], Instruction::IsLt { .. }));
    }

    #[test]
    fn uses_max_bitwidth() {
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let ra = p.fresh_var();
        let rb = p.fresh_var();
        let lt = p.fresh_var();

        p.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::RangeCheck {
            result: ra,
            operand: a,
            bits: 8,
        });
        p.push(Instruction::RangeCheck {
            result: rb,
            operand: b,
            bits: 32,
        });
        p.push(Instruction::IsLt {
            result: lt,
            lhs: a,
            rhs: b,
        });

        let result = bound_inference(&mut p);
        assert_eq!(result.rewritten, 1);
        match &p.instructions[4] {
            Instruction::IsLtBounded { bitwidth, .. } => {
                assert_eq!(*bitwidth, 32); // max(8, 32) = 32
            }
            other => panic!("expected IsLtBounded, got {other:?}"),
        }
    }

    #[test]
    fn rewrites_isle_too() {
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let ra = p.fresh_var();
        let rb = p.fresh_var();
        let le = p.fresh_var();

        p.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::RangeCheck {
            result: ra,
            operand: a,
            bits: 16,
        });
        p.push(Instruction::RangeCheck {
            result: rb,
            operand: b,
            bits: 16,
        });
        p.push(Instruction::IsLe {
            result: le,
            lhs: a,
            rhs: b,
        });

        let result = bound_inference(&mut p);
        assert_eq!(result.rewritten, 1);
        match &p.instructions[4] {
            Instruction::IsLeBounded { bitwidth, .. } => {
                assert_eq!(*bitwidth, 16);
            }
            other => panic!("expected IsLeBounded, got {other:?}"),
        }
    }

    #[test]
    fn no_rewrite_without_rangechecks() {
        let mut p: IrProgram = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let lt = p.fresh_var();

        p.push(Instruction::Input {
            result: a,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: b,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::IsLt {
            result: lt,
            lhs: a,
            rhs: b,
        });

        let result = bound_inference(&mut p);
        assert_eq!(result.rewritten, 0);
    }
}
