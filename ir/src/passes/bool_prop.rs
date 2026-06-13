//! MIRROR CONTRACT: this pass is mirrored by the fused optimizer
//! (`crate::passes::fused`); any semantic change here must land in
//! the mirror too, plus a differential case in the fused parity
//! tests.

use std::collections::HashSet;

use memory::{FieldBackend, FieldElement};

use super::dense::{ConstIndex, DefIndex, DenseVarSet};
use crate::types::{Instruction, IrProgram, IrType, SsaVar};

/// Forward pass that computes the set of SSA variables proven to be boolean
/// (i.e., their value is always 0 or 1).
///
/// Seeds: `Const(0)`, `Const(1)`, `IsEq`, `IsNeq`, `IsLt`, `IsLe` results,
/// `Decompose` bit results, and any variable annotated as `Bool` via `program.var_types`.
///
/// Pattern detection:
/// - `AssertEq(Mul(v, Sub(v, 1)), 0)`: Circom-style boolean enforcement `v*(v-1)=0`
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
/// let mut prog: IrProgram = IrProgram::new();
/// let v = prog.fresh_var();
/// prog.push(Instruction::Input { result: v, name: "b".into(), visibility: Visibility::Witness });
/// prog.set_type(v, IrType::Bool);
/// let booleans = compute_proven_boolean(&prog);
/// assert!(booleans.contains(&v), "annotated Bool var should be in proven_boolean set");
/// ```
pub fn compute_proven_boolean<F: FieldBackend>(program: &IrProgram<F>) -> HashSet<SsaVar> {
    let def_index = DefIndex::build(program);
    let const_index = ConstIndex::build(program);
    proven_boolean_dense(program, &def_index, &const_index)
        .iter()
        .collect()
}

/// Dense-set core of [`compute_proven_boolean`]. The defining-instruction
/// and constant indices are taken as parameters so `optimize()` can share
/// one build across this pass and bit-pattern detection.
pub(crate) fn proven_boolean_dense<F: FieldBackend>(
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
) -> DenseVarSet {
    let mut booleans = DenseVarSet::with_capacity(program.next_var as usize);

    // Seed from type annotations: any variable annotated as Bool is proven boolean
    for (var, ty) in &program.var_types {
        if *ty == IrType::Bool {
            booleans.insert(*var);
        }
    }

    for inst in &program.instructions {
        match inst {
            Instruction::Const { result, value } => {
                if value.is_zero() || *value == FieldElement::<F>::one() {
                    booleans.insert(*result);
                }
            }
            Instruction::IsEq { result, .. }
            | Instruction::IsNeq { result, .. }
            | Instruction::IsLt { result, .. }
            | Instruction::IsLe { result, .. }
            | Instruction::IsLtBounded { result, .. }
            | Instruction::IsLeBounded { result, .. } => {
                booleans.insert(*result);
            }
            Instruction::Not { result, operand } => {
                if booleans.contains(*operand) {
                    booleans.insert(*result);
                }
            }
            Instruction::And { result, lhs, rhs } => {
                if booleans.contains(*lhs) && booleans.contains(*rhs) {
                    booleans.insert(*result);
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                if booleans.contains(*lhs) && booleans.contains(*rhs) {
                    booleans.insert(*result);
                }
            }
            Instruction::Mux {
                result,
                if_true,
                if_false,
                ..
            } => {
                if booleans.contains(*if_true) && booleans.contains(*if_false) {
                    booleans.insert(*result);
                }
            }
            Instruction::RangeCheck { result, bits, .. } => {
                if *bits == 1 {
                    booleans.insert(*result);
                }
            }
            Instruction::Assert {
                result, operand, ..
            } => {
                booleans.insert(*operand);
                booleans.insert(*result);
            }
            // Decompose bit results are boolean by construction
            Instruction::Decompose { bit_results, .. } => {
                for bit in bit_results {
                    booleans.insert(*bit);
                }
            }
            // Detect Circom-style boolean enforcement: AssertEq(Mul(v, Sub(v, 1)), 0)
            Instruction::AssertEq { lhs, rhs, .. } => {
                if let Some(var) =
                    try_detect_boolean_enforcement(*lhs, *rhs, program, def_index, const_index)
                {
                    booleans.insert(var);
                }
                if let Some(var) =
                    try_detect_boolean_enforcement(*rhs, *lhs, program, def_index, const_index)
                {
                    booleans.insert(var);
                }
            }
            _ => {}
        }
    }

    booleans
}

/// Detect `v*(v-1) = 0` boolean enforcement pattern.
///
/// `mul_side` should be the side that might be `Mul(v, Sub(v, 1))`,
/// `zero_side` should be `Const(0)`.
fn try_detect_boolean_enforcement<F: FieldBackend>(
    mul_side: SsaVar,
    zero_side: SsaVar,
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
) -> Option<SsaVar> {
    // zero_side must be Const(0)
    let zero_val = const_index.get(program, zero_side)?;
    if !zero_val.is_zero() {
        return None;
    }

    // mul_side must be Mul(a, b)
    let mul_inst = def_index.get(program, mul_side)?;
    let (a, b) = match mul_inst {
        Instruction::Mul { lhs, rhs, .. } => (*lhs, *rhs),
        _ => return None,
    };

    // One of (a, b) must be Sub(c, Const(1)) where c == the other operand.
    if is_sub_one(b, a, program, def_index, const_index) {
        return Some(a);
    }
    if is_sub_one(a, b, program, def_index, const_index) {
        return Some(b);
    }

    None
}

/// Check if `var` is defined as `Sub(expected_base, Const(1))`.
fn is_sub_one<F: FieldBackend>(
    var: SsaVar,
    expected_base: SsaVar,
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
) -> bool {
    let Some(inst) = def_index.get(program, var) else {
        return false;
    };
    match inst {
        Instruction::Sub { lhs, rhs, .. } => {
            if *lhs != expected_base {
                return false;
            }
            let Some(val) = const_index.get(program, *rhs) else {
                return false;
            };
            *val == FieldElement::<F>::one()
        }
        _ => false,
    }
}
