use std::collections::HashSet;

use memory::FieldElement;

use crate::types::{Instruction, IrProgram, IrType, SsaVar};

/// Forward pass O(n) that computes the set of SSA variables proven to be boolean
/// (i.e., their value is always 0 or 1).
///
/// Seeds: `Const(0)`, `Const(1)`, `IsEq`, `IsNeq`, `IsLt`, `IsLe` results,
/// and any variable annotated as `Bool` via `program.var_types`.
///
/// Propagation:
/// - `Not(x)`: if x is boolean, result is boolean
/// - `And(a, b)`: if both are boolean, result is boolean
/// - `Or(a, b)`: if both are boolean, result is boolean
/// - `Mux(_, t, f)`: if both branches are boolean, result is boolean
///
/// ```
/// use ir::types::{IrProgram, IrType, Instruction, SsaVar, Visibility};
/// use ir::passes::bool_prop::compute_proven_boolean;
///
/// let mut prog = IrProgram::new();
/// let v = prog.fresh_var();
/// prog.push(Instruction::Input { result: v, name: "b".into(), visibility: Visibility::Witness });
/// prog.set_type(v, IrType::Bool);
/// let booleans = compute_proven_boolean(&prog);
/// assert!(booleans.contains(&v), "annotated Bool var should be in proven_boolean set");
/// ```
pub fn compute_proven_boolean(program: &IrProgram) -> HashSet<SsaVar> {
    let mut booleans = HashSet::new();

    // Seed from type annotations: any variable annotated as Bool is proven boolean
    for (var, ty) in &program.var_types {
        if *ty == IrType::Bool {
            booleans.insert(*var);
        }
    }

    for inst in &program.instructions {
        match inst {
            Instruction::Const { result, value } => {
                if value.is_zero() || *value == FieldElement::ONE {
                    booleans.insert(*result);
                }
            }
            Instruction::IsEq { result, .. }
            | Instruction::IsNeq { result, .. }
            | Instruction::IsLt { result, .. }
            | Instruction::IsLe { result, .. } => {
                booleans.insert(*result);
            }
            Instruction::Not { result, operand } => {
                if booleans.contains(operand) {
                    booleans.insert(*result);
                }
            }
            Instruction::And { result, lhs, rhs } => {
                if booleans.contains(lhs) && booleans.contains(rhs) {
                    booleans.insert(*result);
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                if booleans.contains(lhs) && booleans.contains(rhs) {
                    booleans.insert(*result);
                }
            }
            Instruction::Mux {
                result,
                if_true,
                if_false,
                ..
            } => {
                if booleans.contains(if_true) && booleans.contains(if_false) {
                    booleans.insert(*result);
                }
            }
            _ => {}
        }
    }

    booleans
}
