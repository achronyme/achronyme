use std::collections::HashMap;

use constraints::plonkish::{Assignments, Column, PlonkishError};
use memory::FieldElement;

use super::compiler::PlonkishCompiler;
use super::types::PlonkWitnessOp;

// ============================================================================
// PlonkishWitnessGenerator
// ============================================================================

pub struct PlonkishWitnessGenerator {
    ops: Vec<PlonkWitnessOp>,
    col_a: Column,
    col_b: Column,
    col_c: Column,
    col_d: Column,
}

impl PlonkishWitnessGenerator {
    pub fn from_compiler(compiler: &PlonkishCompiler) -> Self {
        Self {
            ops: compiler.witness_ops.clone(),
            col_a: compiler.col_a,
            col_b: compiler.col_b,
            col_c: compiler.col_c,
            col_d: compiler.col_d,
        }
    }

    pub fn generate(
        &self,
        inputs: &HashMap<String, FieldElement>,
        assignments: &mut Assignments,
    ) -> Result<(), PlonkishError> {
        for op in &self.ops {
            match op {
                PlonkWitnessOp::AssignInput { cell, name } => {
                    let val = inputs
                        .get(name)
                        .ok_or_else(|| PlonkishError::MissingInput(name.clone()))?;
                    assignments.set(cell.column, cell.row, *val);
                }
                PlonkWitnessOp::CopyValue { from, to } => {
                    let val = assignments.get(from.column, from.row);
                    assignments.set(to.column, to.row, val);
                }
                PlonkWitnessOp::SetConstant { cell, value } => {
                    assignments.set(cell.column, cell.row, *value);
                }
                PlonkWitnessOp::ArithRow { row } => {
                    let a_val = assignments.get(self.col_a, *row);
                    let b_val = assignments.get(self.col_b, *row);
                    let c_val = assignments.get(self.col_c, *row);
                    let d_val = a_val.mul(&b_val).add(&c_val);
                    assignments.set(self.col_d, *row, d_val);
                }
                PlonkWitnessOp::InverseRow { row } => {
                    let a_val = assignments.get(self.col_a, *row);
                    let inv = a_val
                        .inv()
                        .ok_or_else(|| PlonkishError::MissingInput("division by zero".into()))?;
                    assignments.set(self.col_b, *row, inv);
                    // d = a * inv + 0 = 1
                    assignments.set(self.col_d, *row, FieldElement::ONE);
                }
                PlonkWitnessOp::IsZeroRow { row } => {
                    let a_val = assignments.get(self.col_a, *row);
                    if a_val.is_zero() {
                        // diff == 0: inv = 0, diff*inv = 0
                        assignments.set(self.col_b, *row, FieldElement::ZERO);
                        assignments.set(self.col_d, *row, FieldElement::ZERO);
                    } else {
                        // diff != 0: inv = 1/diff, diff*inv = 1
                        let inv = a_val.inv().ok_or_else(|| {
                            PlonkishError::MissingInput("unexpected zero in IsZero".into())
                        })?;
                        assignments.set(self.col_b, *row, inv);
                        assignments.set(self.col_d, *row, FieldElement::ONE);
                    }
                }
                PlonkWitnessOp::BitExtract {
                    target,
                    source,
                    bit_index,
                } => {
                    let val = assignments.get(source.column, source.row);
                    let limbs = val.to_canonical();
                    let limb_idx = (*bit_index / 64) as usize;
                    let bit_pos = *bit_index % 64;
                    let bit = if limb_idx < 4 {
                        (limbs[limb_idx] >> bit_pos) & 1
                    } else {
                        0
                    };
                    assignments.set(target.column, target.row, FieldElement::from_u64(bit));
                }
            }
        }

        Ok(())
    }
}
