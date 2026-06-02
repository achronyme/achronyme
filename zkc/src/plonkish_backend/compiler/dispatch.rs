use constraints::plonkish::{CellRef, PlonkishError};
use constraints::PoseidonParamsProvider;
use ir::types::{Instruction as IrInstruction, Visibility as IrVisibility};
use memory::{FieldBackend, FieldElement};

use super::super::types::{PlonkVal, PlonkWitnessOp};
use super::PlonkishCompiler;

impl<F: FieldBackend> constraints::ConstraintBackend<F> for PlonkishCompiler<F> {
    type Error = PlonkishError;

    fn compile_instruction(
        &mut self,
        _ir_idx: usize,
        inst: &IrInstruction<F>,
    ) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        match inst {
            IrInstruction::Const { result, value } => {
                self.val_map.insert(*result, PlonkVal::Constant(*value));
            }
            IrInstruction::Input {
                result,
                name,
                visibility,
            } => match visibility {
                IrVisibility::Public => {
                    let cell = CellRef {
                        column: self.col_instance,
                        row: self.instance_row,
                    };
                    self.instance_row += 1;
                    self.bindings.insert(name.clone(), cell);
                    self.public_inputs.push(name.clone());
                    self.witness_ops.push(PlonkWitnessOp::AssignInput {
                        cell,
                        name: name.clone(),
                    });
                    self.val_map.insert(*result, PlonkVal::Cell(cell));
                }
                IrVisibility::Witness => {
                    let row = self.alloc_row();
                    let cell = CellRef {
                        column: self.col_a,
                        row,
                    };
                    self.bindings.insert(name.clone(), cell);
                    self.witnesses.push(name.clone());
                    self.witness_ops.push(PlonkWitnessOp::AssignInput {
                        cell,
                        name: name.clone(),
                    });
                    self.val_map.insert(*result, PlonkVal::Cell(cell));
                }
            },
            IrInstruction::Add { result, lhs, rhs } => {
                let a = self.lookup_val(lhs)?;
                let b = self.lookup_val(rhs)?;
                if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                    self.val_map
                        .insert(*result, PlonkVal::Constant(av.add(&bv)));
                } else {
                    self.val_map
                        .insert(*result, PlonkVal::DeferredAdd(Box::new(a), Box::new(b)));
                }
            }
            IrInstruction::Sub { result, lhs, rhs } => {
                let a = self.lookup_val(lhs)?;
                let b = self.lookup_val(rhs)?;
                if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                    self.val_map
                        .insert(*result, PlonkVal::Constant(av.sub(&bv)));
                } else {
                    self.val_map
                        .insert(*result, PlonkVal::DeferredSub(Box::new(a), Box::new(b)));
                }
            }
            IrInstruction::Neg { result, operand } => {
                let v = self.lookup_val(operand)?;
                if let Some(cv) = v.constant_value() {
                    self.val_map.insert(*result, PlonkVal::Constant(cv.neg()));
                } else {
                    self.val_map
                        .insert(*result, PlonkVal::DeferredNeg(Box::new(v)));
                }
            }
            IrInstruction::Mul { result, lhs, rhs } => {
                let a = self.lookup_val(lhs)?;
                let b = self.lookup_val(rhs)?;
                if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                    self.val_map
                        .insert(*result, PlonkVal::Constant(av.mul(&bv)));
                } else {
                    let a_cell = self.materialize_val(&a)?;
                    let b_cell = self.materialize_val(&b)?;
                    let d_cell = self.emit_arith_row(a_cell, b_cell, None);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
            }
            IrInstruction::Div { result, lhs, rhs } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                if let (Some(av), Some(bv)) = (a_val.constant_value(), b_val.constant_value()) {
                    if let Some(inv) = bv.inv() {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.mul(&inv)));
                    } else {
                        return Err(PlonkishError::MissingInput("division by zero".into()));
                    }
                } else {
                    let num_cell = self.materialize_val(&a_val)?;
                    let den_cell = self.materialize_val(&b_val)?;
                    let d_cell = self.emit_div(num_cell, den_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
            }
            IrInstruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_val = self.lookup_val(cond)?;
                let t_val = self.lookup_val(if_true)?;
                let f_val = self.lookup_val(if_false)?;
                let cond_cell = self.materialize_val(&cond_val)?;
                let t_cell = self.materialize_val(&t_val)?;
                let f_cell = self.materialize_val(&f_val)?;
                let d_cell = self.emit_mux(cond_cell, t_cell, f_cell);
                self.val_map.insert(*result, PlonkVal::Cell(d_cell));
            }
            IrInstruction::AssertEq {
                result, lhs, rhs, ..
            } => {
                let a = self.lookup_val(lhs)?;
                let b = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a)?;
                let b_cell = self.materialize_val(&b)?;
                self.system.add_copy(a_cell, b_cell);
                self.val_map.insert(*result, PlonkVal::Cell(b_cell));
            }
            IrInstruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let left_val = self.lookup_val(left)?;
                let right_val = self.lookup_val(right)?;
                let left_cell = self.materialize_val(&left_val)?;
                let right_cell = self.materialize_val(&right_val)?;
                let d_cell = self.emit_poseidon(left_cell, right_cell)?;
                self.val_map.insert(*result, PlonkVal::Cell(d_cell));
            }
            IrInstruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let op_val = self.lookup_val(operand)?;
                let op_cell = self.materialize_val(&op_val)?;
                self.emit_range_check(op_cell, *bits)?;
                // Record proven bound for IsLt/IsLe optimization
                self.range_bounds.insert(*operand, *bits);
                self.val_map.insert(*result, PlonkVal::Cell(op_cell));
            }
            IrInstruction::Not { result, operand } => {
                self.compile_not(*result, operand)?;
            }
            IrInstruction::And { result, lhs, rhs } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                if !self.proven_boolean.contains(lhs) {
                    self.emit_bool_check(a_cell);
                }
                if !self.proven_boolean.contains(rhs) {
                    self.emit_bool_check(b_cell);
                }
                // result = a * b
                let d_cell = self.emit_arith_row(a_cell, b_cell, None);
                self.val_map.insert(*result, PlonkVal::Cell(d_cell));
            }
            IrInstruction::Or { result, lhs, rhs } => {
                self.compile_or(*result, lhs, rhs)?;
            }
            IrInstruction::IsEq { result, lhs, rhs } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                let eq_cell = self.emit_is_zero(a_cell, b_cell)?;
                self.val_map.insert(*result, PlonkVal::Cell(eq_cell));
            }
            IrInstruction::IsNeq { result, lhs, rhs } => {
                self.compile_is_neq(*result, lhs, rhs)?;
            }
            IrInstruction::IsLt { result, lhs, rhs } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                let bound_a = self.range_bounds.get(lhs).copied();
                let bound_b = self.range_bounds.get(rhs).copied();
                let bound = match (bound_a, bound_b) {
                    (Some(ba), Some(bb)) => Some(ba.max(bb)),
                    _ => None,
                };
                let lt_cell = self.emit_is_lt_bounded(a_cell, b_cell, bound)?;
                self.val_map.insert(*result, PlonkVal::Cell(lt_cell));
            }
            IrInstruction::IsLe { result, lhs, rhs } => {
                self.compile_is_le(*result, lhs, rhs)?;
            }
            IrInstruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                let lt_cell = self.emit_is_lt_bounded(a_cell, b_cell, Some(*bitwidth))?;
                self.val_map.insert(*result, PlonkVal::Cell(lt_cell));
            }
            IrInstruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                self.compile_is_le_bounded(*result, lhs, rhs, *bitwidth)?;
            }
            IrInstruction::Assert {
                result, operand, ..
            } => {
                let op_val = self.lookup_val(operand)?;
                let op_cell = self.materialize_val(&op_val)?;
                if !self.proven_boolean.contains(operand) {
                    self.emit_bool_check(op_cell);
                }
                // Enforce op == 1 via copy constraint to a materialized 1
                let one_cell =
                    self.materialize_val(&PlonkVal::Constant(FieldElement::<F>::one()))?;
                self.system.add_copy(op_cell, one_cell);
                self.val_map.insert(*result, PlonkVal::Cell(op_cell));
            }
            IrInstruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let op_val = self.lookup_val(operand)?;
                let op_cell = self.materialize_val(&op_val)?;
                // Use the same range check path (bit decomposition) but also
                // expose each bit. For plonkish, we decompose into individual
                // advice cells.
                let bit_cells = self.emit_decompose(op_cell, *num_bits)?;
                for (i, bit_ssa) in bit_results.iter().enumerate() {
                    self.val_map.insert(*bit_ssa, PlonkVal::Cell(bit_cells[i]));
                }
                self.range_bounds.insert(*operand, *num_bits);
                self.val_map.insert(*result, PlonkVal::Cell(op_cell));
            }
            IrInstruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                let (q_cell, _r_cell) = self.emit_int_divmod(a_cell, b_cell, *max_bits)?;
                self.val_map.insert(*result, PlonkVal::Cell(q_cell));
            }
            IrInstruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let a_val = self.lookup_val(lhs)?;
                let b_val = self.lookup_val(rhs)?;
                let a_cell = self.materialize_val(&a_val)?;
                let b_cell = self.materialize_val(&b_val)?;
                let (_q_cell, r_cell) = self.emit_int_divmod(a_cell, b_cell, *max_bits)?;
                self.val_map.insert(*result, PlonkVal::Cell(r_cell));
            }
            IrInstruction::WitnessCall { .. } => {
                // Plonkish backend does not yet know how to replay
                // an Artik witness program through its advice-cell
                // model. The R1CS backend handles this natively;
                // compiling a WitnessCall-bearing program through
                // Plonkish should be a dedicated Fase 5 effort.
                return Err(PlonkishError::MissingInput(
                    "WitnessCall (Artik witness program) is not yet supported in the \
                     Plonkish backend — use --prove-backend r1cs"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}
