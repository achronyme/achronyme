use constraints::plonkish::{CellRef, PlonkishError};
use memory::FieldElement;

use super::compiler::PlonkishCompiler;
use super::types::{PlonkVal, PlonkWitnessOp};

// ============================================================================
// Row allocation
// ============================================================================

impl PlonkishCompiler {
    pub(super) fn alloc_row(&mut self) -> usize {
        let row = self.current_row;
        self.current_row += 1;
        if self.current_row > self.system.num_rows {
            self.system.num_rows = self.current_row;
            self.system.assignments.ensure_rows(self.current_row);
        }
        row
    }

    // ========================================================================
    // Wiring: copy value + add copy constraint
    // ========================================================================

    /// Wire a source cell's value to a destination cell.
    /// Records both a witness copy-value op and a verification copy constraint.
    pub(super) fn wire(&mut self, from: CellRef, to: CellRef) {
        self.witness_ops
            .push(PlonkWitnessOp::CopyValue { from, to });
        self.system.add_copy(from, to);
    }

    // ========================================================================
    // Constrain constant: write to fixed column + copy constraint
    // ========================================================================

    /// Set an advice cell to a constant value with a verifier-enforced copy constraint.
    /// 1. Records SetConstant witness op (generator fills the advice cell)
    /// 2. Writes value to col_constant (fixed, verifier-committed)
    /// 3. Adds copy constraint: advice cell == fixed cell
    pub(super) fn constrain_constant(&mut self, cell: CellRef, value: FieldElement) {
        self.witness_ops
            .push(PlonkWitnessOp::SetConstant { cell, value });
        self.system.set(self.col_constant, cell.row, value);
        self.system.add_copy(
            cell,
            CellRef {
                column: self.col_constant,
                row: cell.row,
            },
        );
    }

    // ========================================================================
    // Constrain zero: uses dedicated col_zero fixed column (always zero)
    // ========================================================================

    /// Constrain an advice cell to zero using the dedicated col_zero fixed column.
    /// Unlike `constrain_constant`, this never conflicts with other constants on
    /// the same row because it uses a separate fixed column.
    pub(super) fn constrain_zero(&mut self, cell: CellRef) {
        self.witness_ops.push(PlonkWitnessOp::SetConstant {
            cell,
            value: FieldElement::ZERO,
        });
        // col_zero defaults to zero everywhere — no need to set it
        self.system.add_copy(
            cell,
            CellRef {
                column: self.col_zero,
                row: cell.row,
            },
        );
    }

    // ========================================================================
    // Materialization: PlonkVal → CellRef
    // ========================================================================

    pub(super) fn materialize_val(
        &mut self,
        val: &PlonkVal,
    ) -> Result<CellRef, PlonkishError> {
        self.materialize_val_depth(val, 0)
    }

    /// Recursive materialization with depth tracking to prevent stack overflow
    /// from deeply nested deferred arithmetic (e.g. 10,000 chained additions).
    fn materialize_val_depth(
        &mut self,
        val: &PlonkVal,
        depth: usize,
    ) -> Result<CellRef, PlonkishError> {
        const MAX_DEPTH: usize = 1_000;
        if depth >= MAX_DEPTH {
            return Err(PlonkishError::MissingInput(format!(
                "materialize_val: recursion depth {depth} exceeds limit {MAX_DEPTH} — \
                 circuit has too many chained deferred operations"
            )));
        }
        match val {
            PlonkVal::Cell(cell) => Ok(*cell),
            PlonkVal::Constant(fe) => {
                // Row: 0 * 0 + fe = fe → gate: s*(0*0 + fe - fe) = 0
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                // Constrain col_a to zero so prover cannot inject a*b offset
                self.constrain_zero(CellRef {
                    column: self.col_a,
                    row,
                });
                self.constrain_constant(
                    CellRef {
                        column: self.col_c,
                        row,
                    },
                    *fe,
                );
                self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                Ok(CellRef {
                    column: self.col_d,
                    row,
                })
            }
            PlonkVal::DeferredAdd(a, b) => {
                let a_cell = self.materialize_val_depth(a, depth + 1)?;
                let b_cell = self.materialize_val_depth(b, depth + 1)?;
                // d = a*1 + b
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                self.constrain_constant(
                    CellRef {
                        column: self.col_b,
                        row,
                    },
                    FieldElement::ONE,
                );
                self.wire(
                    a_cell,
                    CellRef {
                        column: self.col_a,
                        row,
                    },
                );
                self.wire(
                    b_cell,
                    CellRef {
                        column: self.col_c,
                        row,
                    },
                );
                self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                Ok(CellRef {
                    column: self.col_d,
                    row,
                })
            }
            PlonkVal::DeferredSub(a, b) => {
                let a_cell = self.materialize_val_depth(a, depth + 1)?;
                let b_cell = self.materialize_val_depth(b, depth + 1)?;
                // d = a - b = a*1 + (-b)
                // Negate b first
                let neg_b = self.negate_cell(b_cell);
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                self.constrain_constant(
                    CellRef {
                        column: self.col_b,
                        row,
                    },
                    FieldElement::ONE,
                );
                self.wire(
                    a_cell,
                    CellRef {
                        column: self.col_a,
                        row,
                    },
                );
                self.wire(
                    neg_b,
                    CellRef {
                        column: self.col_c,
                        row,
                    },
                );
                self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                Ok(CellRef {
                    column: self.col_d,
                    row,
                })
            }
            PlonkVal::DeferredNeg(inner) => {
                let inner_cell = self.materialize_val_depth(inner, depth + 1)?;
                Ok(self.negate_cell(inner_cell))
            }
        }
    }

    /// d = a * (-1) + 0 = -a
    pub(super) fn negate_cell(&mut self, cell: CellRef) -> CellRef {
        let row = self.alloc_row();
        self.system.set(self.col_s_arith, row, FieldElement::ONE);
        self.wire(
            cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row,
            },
            FieldElement::ONE.neg(),
        );
        // Constrain col_c to zero so prover cannot add arbitrary offset
        self.constrain_zero(CellRef {
            column: self.col_c,
            row,
        });
        self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
        CellRef {
            column: self.col_d,
            row,
        }
    }

    // ========================================================================
    // Arithmetic row: d = a*b + c
    // ========================================================================

    pub(super) fn emit_arith_row(
        &mut self,
        a_cell: CellRef,
        b_cell: CellRef,
        c_cell: Option<CellRef>,
    ) -> CellRef {
        let row = self.alloc_row();
        self.system.set(self.col_s_arith, row, FieldElement::ONE);
        self.wire(
            a_cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.wire(
            b_cell,
            CellRef {
                column: self.col_b,
                row,
            },
        );
        if let Some(cc) = c_cell {
            self.wire(
                cc,
                CellRef {
                    column: self.col_c,
                    row,
                },
            );
        } else {
            // Constrain col_c to zero so prover cannot add arbitrary offset
            self.constrain_zero(CellRef {
                column: self.col_c,
                row,
            });
        }
        self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
        CellRef {
            column: self.col_d,
            row,
        }
    }
}

// ============================================================================
// Power-of-two lookup table
// ============================================================================

/// Pre-computed table of 2^0 .. 2^252 as FieldElements.
/// Initialized once on first access, O(253) total instead of O(n) per call.
static POWERS_OF_TWO: std::sync::LazyLock<[FieldElement; 253]> = std::sync::LazyLock::new(|| {
    let mut table = [FieldElement::ZERO; 253];
    table[0] = FieldElement::ONE;
    for i in 1..253 {
        table[i] = table[i - 1].add(&table[i - 1]);
    }
    table
});

/// Look up 2^n from the pre-computed table.
pub(super) fn compute_power_of_two(n: u32) -> FieldElement {
    POWERS_OF_TWO[n as usize]
}
