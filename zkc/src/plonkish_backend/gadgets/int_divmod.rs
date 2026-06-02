use constraints::plonkish::{CellRef, PlonkishError};
use memory::{FieldBackend, FieldElement};

use super::super::compiler::PlonkishCompiler;
use super::super::types::PlonkWitnessOp;

impl<F: FieldBackend> PlonkishCompiler<F> {
    /// Emit constraints for integer division: a = b * q + r, 0 <= r < 2^max_bits.
    /// Returns (q_cell, r_cell).
    pub(in super::super) fn emit_int_divmod(
        &mut self,
        a_cell: CellRef,
        b_cell: CellRef,
        max_bits: u32,
    ) -> Result<(CellRef, CellRef), PlonkishError> {
        // Allocate witness cells for q and r
        let q_row = self.alloc_row();
        let q_cell = CellRef {
            column: self.col_a,
            row: q_row,
        };
        let r_row = self.alloc_row();
        let r_cell = CellRef {
            column: self.col_a,
            row: r_row,
        };

        // Witness ops: compute q and r
        self.witness_ops.push(PlonkWitnessOp::IntDivMod {
            q: q_cell,
            r: r_cell,
            lhs: a_cell,
            rhs: b_cell,
        });

        // Constraint: b * q + r = a  (via arithmetic gate)
        let mul_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, mul_row, FieldElement::<F>::one());
        self.wire(
            b_cell,
            CellRef {
                column: self.col_a,
                row: mul_row,
            },
        );
        self.wire(
            q_cell,
            CellRef {
                column: self.col_b,
                row: mul_row,
            },
        );
        self.wire(
            r_cell,
            CellRef {
                column: self.col_c,
                row: mul_row,
            },
        );
        // d = a*b + c = b*q + r -> constrain d == a
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: mul_row });
        let bq_plus_r = CellRef {
            column: self.col_d,
            row: mul_row,
        };
        self.system.add_copy(bq_plus_r, a_cell);

        // Range check on r and q
        self.enforce_n_range(q_cell, max_bits);
        self.enforce_n_range(r_cell, max_bits);

        // Soundness: enforce r < b by proving (b - r - 1) >= 0
        // Compute b - r - 1 via arithmetic gate: d = b*1 + (-r-1)
        let diff_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, diff_row, FieldElement::<F>::one());
        self.wire(
            b_cell,
            CellRef {
                column: self.col_a,
                row: diff_row,
            },
        );
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: diff_row,
            },
            FieldElement::<F>::one(),
        );
        // c = -(r + 1): materialize r, negate, subtract 1
        // Simpler: use a second gate. First compute r+1, then b-(r+1).
        // Actually, use the gate: d = a*b + c = b*1 + c, set c = -(r+1)
        // We need to create a cell with value -(r+1).
        let neg_r_plus_1_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, neg_r_plus_1_row, FieldElement::<F>::one());
        self.wire(
            r_cell,
            CellRef {
                column: self.col_a,
                row: neg_r_plus_1_row,
            },
        );
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: neg_r_plus_1_row,
            },
            FieldElement::<F>::one().neg(),
        );
        self.constrain_constant(
            CellRef {
                column: self.col_c,
                row: neg_r_plus_1_row,
            },
            FieldElement::<F>::one().neg(),
        );
        // d = r * (-1) + (-1) = -(r+1)
        self.witness_ops.push(PlonkWitnessOp::ArithRow {
            row: neg_r_plus_1_row,
        });
        let neg_r_plus_1 = CellRef {
            column: self.col_d,
            row: neg_r_plus_1_row,
        };

        // Now: d = b*1 + (-(r+1)) = b - r - 1
        self.wire(
            neg_r_plus_1,
            CellRef {
                column: self.col_c,
                row: diff_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: diff_row });
        let b_minus_r_minus_1 = CellRef {
            column: self.col_d,
            row: diff_row,
        };

        self.enforce_n_range(b_minus_r_minus_1, max_bits);

        Ok((q_cell, r_cell))
    }
}
