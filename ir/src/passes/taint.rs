use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Taint level for an SSA variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taint {
    Constant,
    Public,
    Witness,
}

impl Taint {
    fn merge(self, other: Taint) -> Taint {
        match (self, other) {
            (Taint::Witness, _) | (_, Taint::Witness) => Taint::Witness,
            (Taint::Public, _) | (_, Taint::Public) => Taint::Public,
            _ => Taint::Constant,
        }
    }
}

/// A warning emitted by taint analysis.
#[derive(Debug)]
pub enum TaintWarning {
    /// An input variable that appears in computations but never flows into
    /// any `assert_eq` constraint — the prover could supply any value.
    UnderConstrained {
        name: String,
        var: SsaVar,
        visibility: Visibility,
    },
    /// An input variable that is never referenced by any instruction.
    UnusedInput {
        name: String,
        var: SsaVar,
        visibility: Visibility,
    },
}

impl fmt::Display for TaintWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintWarning::UnderConstrained {
                name, visibility, ..
            } => {
                let vis = match visibility {
                    Visibility::Public => "public",
                    Visibility::Witness => "witness",
                };
                write!(f, "{vis} input `{name}` is under-constrained (not in any assert_eq)")
            }
            TaintWarning::UnusedInput {
                name, visibility, ..
            } => {
                let vis = match visibility {
                    Visibility::Public => "public",
                    Visibility::Witness => "witness",
                };
                write!(f, "{vis} input `{name}` is unused")
            }
        }
    }
}

/// Run taint analysis on an IR program.
///
/// Returns the taint map and a list of warnings about under-constrained
/// or unused inputs.
pub fn taint_analysis(program: &IrProgram) -> (HashMap<SsaVar, Taint>, Vec<TaintWarning>) {
    // Collect all input variables
    let mut inputs: Vec<(SsaVar, String, Visibility)> = Vec::new();
    let mut taints: HashMap<SsaVar, Taint> = HashMap::new();
    let mut used_vars: HashSet<SsaVar> = HashSet::new();
    let mut constrained_vars: HashSet<SsaVar> = HashSet::new();

    // Forward pass: compute taints and track usage
    for inst in &program.instructions {
        match inst {
            Instruction::Const { result, .. } => {
                taints.insert(*result, Taint::Constant);
            }
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                let taint = match visibility {
                    Visibility::Public => Taint::Public,
                    Visibility::Witness => Taint::Witness,
                };
                taints.insert(*result, taint);
                inputs.push((*result, name.clone(), *visibility));
            }
            Instruction::Add { result, lhs, rhs }
            | Instruction::Sub { result, lhs, rhs }
            | Instruction::Mul { result, lhs, rhs }
            | Instruction::Div { result, lhs, rhs } => {
                used_vars.insert(*lhs);
                used_vars.insert(*rhs);
                let t = taint_of(&taints, *lhs).merge(taint_of(&taints, *rhs));
                taints.insert(*result, t);
            }
            Instruction::Neg { result, operand } => {
                used_vars.insert(*operand);
                taints.insert(*result, taint_of(&taints, *operand));
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                used_vars.insert(*cond);
                used_vars.insert(*if_true);
                used_vars.insert(*if_false);
                let t = taint_of(&taints, *cond)
                    .merge(taint_of(&taints, *if_true))
                    .merge(taint_of(&taints, *if_false));
                taints.insert(*result, t);
            }
            Instruction::AssertEq { result, lhs, rhs } => {
                used_vars.insert(*lhs);
                used_vars.insert(*rhs);
                constrained_vars.insert(*lhs);
                constrained_vars.insert(*rhs);
                let t = taint_of(&taints, *lhs).merge(taint_of(&taints, *rhs));
                taints.insert(*result, t);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                used_vars.insert(*left);
                used_vars.insert(*right);
                let t = taint_of(&taints, *left).merge(taint_of(&taints, *right));
                taints.insert(*result, t);
            }
            Instruction::RangeCheck {
                result, operand, ..
            } => {
                used_vars.insert(*operand);
                constrained_vars.insert(*operand);
                taints.insert(*result, taint_of(&taints, *operand));
            }
            Instruction::Not { result, operand } => {
                used_vars.insert(*operand);
                taints.insert(*result, taint_of(&taints, *operand));
            }
            Instruction::And { result, lhs, rhs }
            | Instruction::Or { result, lhs, rhs }
            | Instruction::IsEq { result, lhs, rhs }
            | Instruction::IsNeq { result, lhs, rhs }
            | Instruction::IsLt { result, lhs, rhs }
            | Instruction::IsLe { result, lhs, rhs } => {
                used_vars.insert(*lhs);
                used_vars.insert(*rhs);
                let t = taint_of(&taints, *lhs).merge(taint_of(&taints, *rhs));
                taints.insert(*result, t);
            }
            Instruction::Assert { result, operand } => {
                used_vars.insert(*operand);
                constrained_vars.insert(*operand);
                taints.insert(*result, taint_of(&taints, *operand));
            }
        }
    }

    // Backward fixpoint: propagate constrained status transitively.
    // If a result is constrained, its operands are also constrained.
    // SSA is acyclic, so we iterate backward until no changes.
    loop {
        let mut changed = false;
        for inst in program.instructions.iter().rev() {
            let result = inst.result_var();
            if constrained_vars.contains(&result) {
                for op in inst.operands() {
                    if constrained_vars.insert(op) {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Generate warnings
    let mut warnings = Vec::new();
    for (var, name, visibility) in &inputs {
        if !used_vars.contains(var) {
            warnings.push(TaintWarning::UnusedInput {
                name: name.clone(),
                var: *var,
                visibility: *visibility,
            });
        } else if !constrained_vars.contains(var) {
            warnings.push(TaintWarning::UnderConstrained {
                name: name.clone(),
                var: *var,
                visibility: *visibility,
            });
        }
    }

    (taints, warnings)
}

fn taint_of(taints: &HashMap<SsaVar, Taint>, var: SsaVar) -> Taint {
    taints.get(&var).copied().unwrap_or(Taint::Constant)
}
