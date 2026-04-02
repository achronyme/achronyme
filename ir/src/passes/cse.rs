//! Common Sub-expression Elimination (CSE) pass.
//!
//! Replaces duplicate computations with references to the first occurrence.
//! A subsequent DCE pass will remove the now-unused duplicate instructions.
//!
//! Only pure (side-effect-free) instructions are candidates for elimination.
//! Side-effecting instructions (AssertEq, Assert, Input, RangeCheck) are
//! never deduplicated even if they have identical operands.

use std::collections::HashMap;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// A canonical key for an instruction, ignoring its result variable.
/// Two instructions with the same key compute the same value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum CseKey {
    Add(SsaVar, SsaVar),
    Sub(SsaVar, SsaVar),
    Mul(SsaVar, SsaVar),
    Div(SsaVar, SsaVar),
    Neg(SsaVar),
    Mux(SsaVar, SsaVar, SsaVar),
    PoseidonHash(SsaVar, SsaVar),
    Not(SsaVar),
    And(SsaVar, SsaVar),
    Or(SsaVar, SsaVar),
    IsEq(SsaVar, SsaVar),
    IsNeq(SsaVar, SsaVar),
    IsLt(SsaVar, SsaVar),
    IsLe(SsaVar, SsaVar),
    IsLtBounded(SsaVar, SsaVar, u32),
    IsLeBounded(SsaVar, SsaVar, u32),
    IntDiv(SsaVar, SsaVar, u32),
    IntMod(SsaVar, SsaVar, u32),
}

/// Extract a CSE key from an instruction, if it's a pure computation.
fn cse_key<F: FieldBackend>(inst: &Instruction<F>) -> Option<CseKey> {
    match inst {
        Instruction::Add { lhs, rhs, .. } => Some(CseKey::Add(*lhs, *rhs)),
        Instruction::Sub { lhs, rhs, .. } => Some(CseKey::Sub(*lhs, *rhs)),
        Instruction::Mul { lhs, rhs, .. } => Some(CseKey::Mul(*lhs, *rhs)),
        Instruction::Div { lhs, rhs, .. } => Some(CseKey::Div(*lhs, *rhs)),
        Instruction::Neg { operand, .. } => Some(CseKey::Neg(*operand)),
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => Some(CseKey::Mux(*cond, *if_true, *if_false)),
        Instruction::PoseidonHash { left, right, .. } => Some(CseKey::PoseidonHash(*left, *right)),
        Instruction::Not { operand, .. } => Some(CseKey::Not(*operand)),
        Instruction::And { lhs, rhs, .. } => Some(CseKey::And(*lhs, *rhs)),
        Instruction::Or { lhs, rhs, .. } => Some(CseKey::Or(*lhs, *rhs)),
        Instruction::IsEq { lhs, rhs, .. } => Some(CseKey::IsEq(*lhs, *rhs)),
        Instruction::IsNeq { lhs, rhs, .. } => Some(CseKey::IsNeq(*lhs, *rhs)),
        Instruction::IsLt { lhs, rhs, .. } => Some(CseKey::IsLt(*lhs, *rhs)),
        Instruction::IsLe { lhs, rhs, .. } => Some(CseKey::IsLe(*lhs, *rhs)),
        Instruction::IsLtBounded {
            lhs, rhs, bitwidth, ..
        } => Some(CseKey::IsLtBounded(*lhs, *rhs, *bitwidth)),
        Instruction::IsLeBounded {
            lhs, rhs, bitwidth, ..
        } => Some(CseKey::IsLeBounded(*lhs, *rhs, *bitwidth)),
        // Side-effecting or unique instructions — never deduplicate
        Instruction::Const { .. }
        | Instruction::Input { .. }
        | Instruction::AssertEq { .. }
        | Instruction::Assert { .. }
        | Instruction::RangeCheck { .. }
        | Instruction::Decompose { .. } => None,
        Instruction::IntDiv {
            lhs, rhs, max_bits, ..
        } => Some(CseKey::IntDiv(*lhs, *rhs, *max_bits)),
        Instruction::IntMod {
            lhs, rhs, max_bits, ..
        } => Some(CseKey::IntMod(*lhs, *rhs, *max_bits)),
    }
}

/// Run CSE on an IR program. Returns the number of eliminated sub-expressions.
///
/// For each duplicate computation, the result variable is remapped to the
/// first occurrence. The duplicate instruction is retained but becomes dead
/// (unreferenced) and will be removed by a subsequent DCE pass.
pub fn common_subexpression_elimination<F: FieldBackend>(program: &mut IrProgram<F>) -> usize {
    // Map: CseKey → first result variable that computed this expression.
    let mut seen: HashMap<CseKey, SsaVar> = HashMap::new();
    // Map: old result var → replacement var (from first occurrence).
    let mut replacements: HashMap<SsaVar, SsaVar> = HashMap::new();
    let mut eliminated = 0;

    // Pass 1: identify duplicates
    for inst in &program.instructions {
        if let Some(key) = cse_key(inst) {
            // Canonicalize the key through existing replacements so that
            // chains of substitutions are handled correctly.
            let canon_key = canonicalize_key(&key, &replacements);
            let result = inst.result_var();
            if let Some(&existing) = seen.get(&canon_key) {
                replacements.insert(result, existing);
                eliminated += 1;
            } else {
                seen.insert(canon_key, result);
            }
        }
    }

    if eliminated == 0 {
        return 0;
    }

    // Pass 2: rewrite all operand references through the replacement map
    for inst in &mut program.instructions {
        rewrite_operands(inst, &replacements);
    }

    eliminated
}

/// Canonicalize a CseKey by applying replacements to its operands.
fn canonicalize_key(key: &CseKey, replacements: &HashMap<SsaVar, SsaVar>) -> CseKey {
    let r = |v: &SsaVar| -> SsaVar { *replacements.get(v).unwrap_or(v) };
    match key {
        CseKey::Add(a, b) => CseKey::Add(r(a), r(b)),
        CseKey::Sub(a, b) => CseKey::Sub(r(a), r(b)),
        CseKey::Mul(a, b) => CseKey::Mul(r(a), r(b)),
        CseKey::Div(a, b) => CseKey::Div(r(a), r(b)),
        CseKey::Neg(a) => CseKey::Neg(r(a)),
        CseKey::Mux(c, t, f) => CseKey::Mux(r(c), r(t), r(f)),
        CseKey::PoseidonHash(l, ri) => CseKey::PoseidonHash(r(l), r(ri)),
        CseKey::Not(a) => CseKey::Not(r(a)),
        CseKey::And(a, b) => CseKey::And(r(a), r(b)),
        CseKey::Or(a, b) => CseKey::Or(r(a), r(b)),
        CseKey::IsEq(a, b) => CseKey::IsEq(r(a), r(b)),
        CseKey::IsNeq(a, b) => CseKey::IsNeq(r(a), r(b)),
        CseKey::IsLt(a, b) => CseKey::IsLt(r(a), r(b)),
        CseKey::IsLe(a, b) => CseKey::IsLe(r(a), r(b)),
        CseKey::IsLtBounded(a, b, w) => CseKey::IsLtBounded(r(a), r(b), *w),
        CseKey::IsLeBounded(a, b, w) => CseKey::IsLeBounded(r(a), r(b), *w),
        CseKey::IntDiv(a, b, w) => CseKey::IntDiv(r(a), r(b), *w),
        CseKey::IntMod(a, b, w) => CseKey::IntMod(r(a), r(b), *w),
    }
}

/// Rewrite operand references in an instruction using the replacement map.
fn rewrite_operands<F: FieldBackend>(inst: &mut Instruction<F>, replacements: &HashMap<SsaVar, SsaVar>) {
    let r = |v: &mut SsaVar| {
        if let Some(&repl) = replacements.get(v) {
            *v = repl;
        }
    };
    match inst {
        Instruction::Const { .. } | Instruction::Input { .. } => {}
        Instruction::Add { lhs, rhs, .. }
        | Instruction::Sub { lhs, rhs, .. }
        | Instruction::Mul { lhs, rhs, .. }
        | Instruction::Div { lhs, rhs, .. } => {
            r(lhs);
            r(rhs);
        }
        Instruction::Neg { operand, .. }
        | Instruction::Not { operand, .. }
        | Instruction::Assert { operand, .. } => {
            r(operand);
        }
        Instruction::And { lhs, rhs, .. }
        | Instruction::Or { lhs, rhs, .. }
        | Instruction::IsEq { lhs, rhs, .. }
        | Instruction::IsNeq { lhs, rhs, .. }
        | Instruction::IsLt { lhs, rhs, .. }
        | Instruction::IsLe { lhs, rhs, .. }
        | Instruction::IsLtBounded { lhs, rhs, .. }
        | Instruction::IsLeBounded { lhs, rhs, .. } => {
            r(lhs);
            r(rhs);
        }
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => {
            r(cond);
            r(if_true);
            r(if_false);
        }
        Instruction::AssertEq { lhs, rhs, .. } => {
            r(lhs);
            r(rhs);
        }
        Instruction::PoseidonHash { left, right, .. } => {
            r(left);
            r(right);
        }
        Instruction::RangeCheck { operand, .. } => {
            r(operand);
        }
        Instruction::Decompose { operand, .. } => {
            r(operand);
        }
        Instruction::IntDiv { lhs, rhs, .. } | Instruction::IntMod { lhs, rhs, .. } => {
            r(lhs);
            r(rhs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IrProgram, SsaVar};

    fn var(n: u32) -> SsaVar {
        SsaVar(n)
    }

    fn make_program(instructions: Vec<Instruction>, next_var: u32) -> IrProgram {
        IrProgram {
            instructions,
            next_var,
            ..Default::default()
        }
    }

    #[test]
    fn cse_eliminates_duplicate_add() {
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "x".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Input {
                    result: var(1),
                    name: "y".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Add {
                    result: var(2),
                    lhs: var(0),
                    rhs: var(1),
                },
                Instruction::Add {
                    result: var(3),
                    lhs: var(0),
                    rhs: var(1),
                },
                Instruction::AssertEq {
                    result: var(4),
                    lhs: var(2),
                    rhs: var(3),
                    message: None,
                },
            ],
            5,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        assert_eq!(eliminated, 1);

        // The assert_eq should now reference var(2) for both sides
        if let Instruction::AssertEq { lhs, rhs, .. } = &program.instructions[4] {
            assert_eq!(*lhs, var(2));
            assert_eq!(*rhs, var(2));
        } else {
            panic!("expected AssertEq");
        }
    }

    #[test]
    fn cse_eliminates_duplicate_poseidon() {
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "a".into(),
                    visibility: crate::types::Visibility::Witness,
                },
                Instruction::Input {
                    result: var(1),
                    name: "b".into(),
                    visibility: crate::types::Visibility::Witness,
                },
                Instruction::PoseidonHash {
                    result: var(2),
                    left: var(0),
                    right: var(1),
                },
                Instruction::PoseidonHash {
                    result: var(3),
                    left: var(0),
                    right: var(1),
                },
                Instruction::AssertEq {
                    result: var(4),
                    lhs: var(2),
                    rhs: var(3),
                    message: None,
                },
            ],
            5,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        assert_eq!(eliminated, 1);
    }

    #[test]
    fn cse_does_not_eliminate_different_operands() {
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "a".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Input {
                    result: var(1),
                    name: "b".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Add {
                    result: var(2),
                    lhs: var(0),
                    rhs: var(1),
                },
                Instruction::Sub {
                    result: var(3),
                    lhs: var(0),
                    rhs: var(1),
                },
            ],
            4,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        assert_eq!(eliminated, 0);
    }

    #[test]
    fn cse_does_not_eliminate_side_effects() {
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "x".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Input {
                    result: var(1),
                    name: "y".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::AssertEq {
                    result: var(2),
                    lhs: var(0),
                    rhs: var(1),
                    message: None,
                },
                Instruction::AssertEq {
                    result: var(3),
                    lhs: var(0),
                    rhs: var(1),
                    message: None,
                },
            ],
            4,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        assert_eq!(eliminated, 0);
    }

    #[test]
    fn cse_chain_replacement() {
        // a = x + y
        // b = x + y  (duplicate of a)
        // c = b * b  (uses b, should become a * a)
        // d = a * a  (duplicate of c after replacement)
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "x".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Input {
                    result: var(1),
                    name: "y".into(),
                    visibility: crate::types::Visibility::Public,
                },
                Instruction::Add {
                    result: var(2),
                    lhs: var(0),
                    rhs: var(1),
                },
                Instruction::Add {
                    result: var(3),
                    lhs: var(0),
                    rhs: var(1),
                },
                Instruction::Mul {
                    result: var(4),
                    lhs: var(3),
                    rhs: var(3),
                },
                Instruction::Mul {
                    result: var(5),
                    lhs: var(2),
                    rhs: var(2),
                },
                Instruction::AssertEq {
                    result: var(6),
                    lhs: var(4),
                    rhs: var(5),
                    message: None,
                },
            ],
            7,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        // var(3) = var(2), then var(4) uses var(2)*var(2) = same as var(5)
        assert_eq!(eliminated, 2);
    }

    #[test]
    fn cse_poseidon_different_order_not_eliminated() {
        // poseidon(a, b) != poseidon(b, a) — order matters for hashes
        let mut program = make_program(
            vec![
                Instruction::Input {
                    result: var(0),
                    name: "a".into(),
                    visibility: crate::types::Visibility::Witness,
                },
                Instruction::Input {
                    result: var(1),
                    name: "b".into(),
                    visibility: crate::types::Visibility::Witness,
                },
                Instruction::PoseidonHash {
                    result: var(2),
                    left: var(0),
                    right: var(1),
                },
                Instruction::PoseidonHash {
                    result: var(3),
                    left: var(1),
                    right: var(0),
                },
            ],
            4,
        );

        let eliminated = common_subexpression_elimination(&mut program);
        assert_eq!(eliminated, 0);
    }
}
