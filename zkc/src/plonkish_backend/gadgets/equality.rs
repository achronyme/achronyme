use constraints::plonkish::{CellRef, PlonkishError};
use memory::{FieldBackend, FieldElement};

use super::super::compiler::PlonkishCompiler;
use super::super::types::{PlonkVal, PlonkWitnessOp};

impl<F: FieldBackend> PlonkishCompiler<F> {
    pub(in super::super) fn emit_is_zero(
        &mut self,
        a: CellRef,
        b: CellRef,
    ) -> Result<CellRef, PlonkishError> {
        // diff = a - b (witness computation row, gate is tautological)
        let neg_b = self.negate_cell(b);
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
            a,
            CellRef {
                column: self.col_a,
                row: diff_row,
            },
        );
        self.wire(
            neg_b,
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

        // inv row: if diff != 0 then inv=1/diff, d=1; else inv=0, d=0
        // Uses IsZeroRow (handles diff=0 without erroring, unlike InverseRow)
        let inv_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, inv_row, FieldElement::<F>::one());
        self.wire(
            diff,
            CellRef {
                column: self.col_a,
                row: inv_row,
            },
        );
        // Constrain col_c to zero (defense in depth — also transitively constrained by enforce_row)
        self.constrain_zero(CellRef {
            column: self.col_c,
            row: inv_row,
        });
        self.witness_ops
            .push(PlonkWitnessOp::IsZeroRow { row: inv_row });
        let inv_cell = CellRef {
            column: self.col_b,
            row: inv_row,
        };
        let diff_times_inv = CellRef {
            column: self.col_d,
            row: inv_row,
        };

        // eq = 1 - diff*inv (witness computation row)
        let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::<F>::one()))?;
        let neg_dti = self.negate_cell(diff_times_inv);
        let eq_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, eq_row, FieldElement::<F>::one());
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: eq_row,
            },
            FieldElement::<F>::one(),
        );
        self.wire(
            one_cell,
            CellRef {
                column: self.col_a,
                row: eq_row,
            },
        );
        self.wire(
            neg_dti,
            CellRef {
                column: self.col_c,
                row: eq_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: eq_row });
        let eq_cell = CellRef {
            column: self.col_d,
            row: eq_row,
        };

        // CONSTRAINT 1: diff * inv + eq = 1
        // d=1 is copy-constrained to fixed column so the gate actually constrains the relationship.
        // Gate: s_arith * (a*b + c - d) = 0  →  diff*inv + eq - 1 = 0
        let enforce_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, enforce_row, FieldElement::<F>::one());
        self.wire(
            diff,
            CellRef {
                column: self.col_a,
                row: enforce_row,
            },
        );
        self.wire(
            inv_cell,
            CellRef {
                column: self.col_b,
                row: enforce_row,
            },
        );
        self.wire(
            eq_cell,
            CellRef {
                column: self.col_c,
                row: enforce_row,
            },
        );
        self.constrain_constant(
            CellRef {
                column: self.col_d,
                row: enforce_row,
            },
            FieldElement::<F>::one(),
        );

        // CONSTRAINT 2: diff * eq = 0
        // d=0 is copy-constrained to fixed column so the gate constrains diff*eq = 0.
        let check_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, check_row, FieldElement::<F>::one());
        self.wire(
            diff,
            CellRef {
                column: self.col_a,
                row: check_row,
            },
        );
        self.wire(
            eq_cell,
            CellRef {
                column: self.col_b,
                row: check_row,
            },
        );
        // Constrain col_c to zero so diff*eq + 0 = 0 is enforced exactly
        self.constrain_zero(CellRef {
            column: self.col_c,
            row: check_row,
        });
        self.constrain_zero(CellRef {
            column: self.col_d,
            row: check_row,
        });

        Ok(eq_cell)
    }
}
