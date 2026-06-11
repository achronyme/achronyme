use memory::FieldBackend;

use super::{Instruction, SsaVar};

impl<F: FieldBackend> Instruction<F> {
    /// Visit every operand (read variable) of this instruction, in the
    /// same order [`Instruction::operands`] returns them, without
    /// allocating a `Vec`. Liveness-style passes that scan millions of
    /// instructions per run use this to keep the traversal
    /// allocation-free.
    pub fn for_each_operand(&self, mut f: impl FnMut(SsaVar)) {
        match self {
            Instruction::Const { .. } | Instruction::Input { .. } => {}
            Instruction::Add { lhs, rhs, .. }
            | Instruction::Sub { lhs, rhs, .. }
            | Instruction::Mul { lhs, rhs, .. }
            | Instruction::Div { lhs, rhs, .. }
            | Instruction::And { lhs, rhs, .. }
            | Instruction::Or { lhs, rhs, .. }
            | Instruction::IsEq { lhs, rhs, .. }
            | Instruction::IsNeq { lhs, rhs, .. }
            | Instruction::IsLt { lhs, rhs, .. }
            | Instruction::IsLe { lhs, rhs, .. }
            | Instruction::IsLtBounded { lhs, rhs, .. }
            | Instruction::IsLeBounded { lhs, rhs, .. }
            | Instruction::AssertEq { lhs, rhs, .. }
            | Instruction::IntDiv { lhs, rhs, .. }
            | Instruction::IntMod { lhs, rhs, .. } => {
                f(*lhs);
                f(*rhs);
            }
            Instruction::Neg { operand, .. }
            | Instruction::Not { operand, .. }
            | Instruction::Assert { operand, .. }
            | Instruction::RangeCheck { operand, .. }
            | Instruction::Decompose { operand, .. } => f(*operand),
            Instruction::Mux {
                cond,
                if_true,
                if_false,
                ..
            } => {
                f(*cond);
                f(*if_true);
                f(*if_false);
            }
            Instruction::PoseidonHash { left, right, .. } => {
                f(*left);
                f(*right);
            }
            Instruction::WitnessCall(call) => {
                for v in &call.inputs {
                    f(*v);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use memory::FieldElement;

    use crate::types::{Instruction, SsaVar, WitnessCallBody};

    fn collect(inst: &Instruction) -> Vec<SsaVar> {
        let mut out = Vec::new();
        inst.for_each_operand(|v| out.push(v));
        out
    }

    #[test]
    fn matches_operands_on_every_shape() {
        let v = |n: u64| SsaVar(n);
        let insts: Vec<Instruction> = vec![
            Instruction::Const {
                result: v(0),
                value: FieldElement::from_u64(7),
            },
            Instruction::Add {
                result: v(1),
                lhs: v(2),
                rhs: v(2),
            },
            Instruction::Mux {
                result: v(3),
                cond: v(4),
                if_true: v(5),
                if_false: v(6),
            },
            Instruction::Neg {
                result: v(7),
                operand: v(8),
            },
            Instruction::WitnessCall(Box::new(WitnessCallBody {
                outputs: vec![v(9)],
                inputs: vec![v(10), v(11), v(10)],
                program_bytes: vec![],
            })),
        ];
        for inst in &insts {
            assert_eq!(collect(inst), inst.operands(), "mismatch on {inst}");
        }
    }
}
