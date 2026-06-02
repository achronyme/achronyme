use constraints::plonkish::{CellRef, PlonkishError};
use constraints::PoseidonParamsProvider;
use ir::types::SsaVar;
use memory::{FieldBackend, FieldElement};

use super::super::types::{PlonkVal, PlonkWitnessOp};
use super::PlonkishCompiler;

impl<F: FieldBackend> PlonkishCompiler<F> {
    pub(super) fn compile_not(
        &mut self,
        result: SsaVar,
        operand: &SsaVar,
    ) -> Result<(), PlonkishError> {
        let op_val = self.lookup_val(operand)?;
        let op_cell = self.materialize_val(&op_val)?;
        if !self.proven_boolean.contains(operand) {
            self.emit_bool_check(op_cell);
        }
        // result = 1 - op: d = op * (-1) + 1
        let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::<F>::one()))?;
        let neg_op = self.negate_cell(op_cell);
        let row = self.alloc_row();
        self.system
            .set(self.col_s_arith, row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            neg_op,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.wire(
            one_cell,
            CellRef {
                column: self.col_c,
                row,
            },
        );
        self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
        self.val_map.insert(
            result,
            PlonkVal::Cell(CellRef {
                column: self.col_d,
                row,
            }),
        );
        Ok(())
    }

    pub(super) fn compile_or(
        &mut self,
        result: SsaVar,
        lhs: &SsaVar,
        rhs: &SsaVar,
    ) -> Result<(), PlonkishError> {
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
        // result = a + b - a*b
        let product = self.emit_arith_row(a_cell, b_cell, None);
        let neg_product = self.negate_cell(product);
        // sum = a*1 + b
        let sum_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, sum_row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: sum_row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            a_cell,
            CellRef {
                column: self.col_a,
                row: sum_row,
            },
        );
        self.wire(
            b_cell,
            CellRef {
                column: self.col_c,
                row: sum_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: sum_row });
        let sum_cell = CellRef {
            column: self.col_d,
            row: sum_row,
        };
        // result = sum*1 + neg_product
        let result_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, result_row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: result_row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            sum_cell,
            CellRef {
                column: self.col_a,
                row: result_row,
            },
        );
        self.wire(
            neg_product,
            CellRef {
                column: self.col_c,
                row: result_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: result_row });
        self.val_map.insert(
            result,
            PlonkVal::Cell(CellRef {
                column: self.col_d,
                row: result_row,
            }),
        );
        Ok(())
    }

    pub(super) fn compile_is_neq(
        &mut self,
        result: SsaVar,
        lhs: &SsaVar,
        rhs: &SsaVar,
    ) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        let a_val = self.lookup_val(lhs)?;
        let b_val = self.lookup_val(rhs)?;
        let a_cell = self.materialize_val(&a_val)?;
        let b_cell = self.materialize_val(&b_val)?;
        let eq_cell = self.emit_is_zero(a_cell, b_cell)?;
        self.compile_one_minus(result, eq_cell)
    }

    pub(super) fn compile_is_le(
        &mut self,
        result: SsaVar,
        lhs: &SsaVar,
        rhs: &SsaVar,
    ) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        // a <= b ≡ !(b < a) ≡ 1 - IsLt(b, a)
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
        let lt_cell = self.emit_is_lt_bounded(b_cell, a_cell, bound)?;
        self.compile_one_minus(result, lt_cell)
    }

    pub(super) fn compile_is_le_bounded(
        &mut self,
        result: SsaVar,
        lhs: &SsaVar,
        rhs: &SsaVar,
        bitwidth: u32,
    ) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        let a_val = self.lookup_val(lhs)?;
        let b_val = self.lookup_val(rhs)?;
        let a_cell = self.materialize_val(&a_val)?;
        let b_cell = self.materialize_val(&b_val)?;
        let lt_cell = self.emit_is_lt_bounded(b_cell, a_cell, Some(bitwidth))?;
        self.compile_one_minus(result, lt_cell)
    }

    fn compile_one_minus(&mut self, result: SsaVar, cell: CellRef) -> Result<(), PlonkishError> {
        let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::<F>::one()))?;
        let neg_cell = self.negate_cell(cell);
        let row = self.alloc_row();
        self.system
            .set(self.col_s_arith, row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            one_cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.wire(
            neg_cell,
            CellRef {
                column: self.col_c,
                row,
            },
        );
        self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
        self.val_map.insert(
            result,
            PlonkVal::Cell(CellRef {
                column: self.col_d,
                row,
            }),
        );
        Ok(())
    }
}
