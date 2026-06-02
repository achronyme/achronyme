use constraints::plonkish::CellRef;
use memory::{FieldBackend, FieldElement};

use super::super::compiler::PlonkishCompiler;
use super::super::types::PlonkWitnessOp;

impl<F: FieldBackend> PlonkishCompiler<F> {
    pub(in super::super) fn emit_div(&mut self, num: CellRef, den: CellRef) -> CellRef {
        // Row 1: den * inv = 1
        let inv_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, inv_row, FieldElement::<F>::one());
        self.wire(
            den,
            CellRef {
                column: self.col_a,
                row: inv_row,
            },
        );
        // b = inv (filled by InverseRow)
        // c = 0 (constrain to zero so den*inv = 1 is enforced exactly)
        self.constrain_zero(CellRef {
            column: self.col_c,
            row: inv_row,
        });
        // d = 1 (set as constant, copy-constrained to fixed column)
        self.constrain_constant(
            CellRef {
                column: self.col_d,
                row: inv_row,
            },
            FieldElement::<F>::one(),
        );
        self.witness_ops
            .push(PlonkWitnessOp::InverseRow { row: inv_row });
        let inv_cell = CellRef {
            column: self.col_b,
            row: inv_row,
        };

        // Row 2: num * inv + 0 = result
        self.emit_arith_row(num, inv_cell, None)
    }

    pub(in super::super) fn emit_mux(&mut self, cond: CellRef, t: CellRef, f: CellRef) -> CellRef {
        // Row 1: cond^2 = cond (boolean enforcement)
        // Gate: s*(a*b+c-d)=0 → s*(cond*cond+0-cond)=0 → cond^2=cond
        let bool_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, bool_row, FieldElement::<F>::one());
        self.wire(
            cond,
            CellRef {
                column: self.col_a,
                row: bool_row,
            },
        );
        self.wire(
            cond,
            CellRef {
                column: self.col_b,
                row: bool_row,
            },
        );
        self.wire(
            cond,
            CellRef {
                column: self.col_d,
                row: bool_row,
            },
        );
        // Constrain col_c to zero so cond^2 + 0 = cond is enforced exactly
        self.constrain_zero(CellRef {
            column: self.col_c,
            row: bool_row,
        });
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: bool_row });

        // diff = t - f
        let neg_f = self.negate_cell(f);
        let diff_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, diff_row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: diff_row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            t,
            CellRef {
                column: self.col_a,
                row: diff_row,
            },
        );
        self.wire(
            neg_f,
            CellRef {
                column: self.col_c,
                row: diff_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: diff_row });
        let diff = CellRef {
            column: self.col_d,
            row: diff_row,
        };

        // result = cond * diff + f
        self.emit_arith_row(cond, diff, Some(f))
    }

    pub(in super::super) fn emit_bool_check(&mut self, cell: CellRef) {
        let row = self.alloc_row();
        self.system
            .set(self.col_s_arith, row, FieldElement::<F>::one());
        self.wire(
            cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.wire(
            cell,
            CellRef {
                column: self.col_b,
                row,
            },
        );
        self.wire(
            cell,
            CellRef {
                column: self.col_d,
                row,
            },
        );
        // Constrain col_c to zero so cell^2 + 0 = cell is enforced exactly
        self.constrain_zero(CellRef {
            column: self.col_c,
            row,
        });
        self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
    }
}
