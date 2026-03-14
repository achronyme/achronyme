use constraints::plonkish::{CellRef, Expression, LookupTable, PlonkishError};
use memory::FieldElement;

use super::compiler::PlonkishCompiler;
use super::primitives::compute_power_of_two;
use super::types::{PlonkVal, PlonkWitnessOp};

impl PlonkishCompiler {
    // ========================================================================
    // Division: 2 rows
    // ========================================================================

    pub(super) fn emit_div(&mut self, num: CellRef, den: CellRef) -> CellRef {
        // Row 1: den * inv = 1
        let inv_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, inv_row, FieldElement::ONE);
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
            FieldElement::ONE,
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

    // ========================================================================
    // MUX: boolean check + subtraction + selection
    // ========================================================================

    pub(super) fn emit_mux(&mut self, cond: CellRef, t: CellRef, f: CellRef) -> CellRef {
        // Row 1: cond^2 = cond (boolean enforcement)
        // Gate: s*(a*b+c-d)=0 → s*(cond*cond+0-cond)=0 → cond^2=cond
        let bool_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, bool_row, FieldElement::ONE);
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
            .set(self.col_s_arith, diff_row, FieldElement::ONE);
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: diff_row,
            },
            FieldElement::ONE,
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

    // ========================================================================
    // Boolean check: op^2 = op
    // ========================================================================

    pub(super) fn emit_bool_check(&mut self, cell: CellRef) {
        let row = self.alloc_row();
        self.system.set(self.col_s_arith, row, FieldElement::ONE);
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

    // ========================================================================
    // IsZero gadget: returns a cell that is 1 if a == b, 0 otherwise
    // ========================================================================

    pub(super) fn emit_is_zero(&mut self, a: CellRef, b: CellRef) -> CellRef {
        // diff = a - b (witness computation row, gate is tautological)
        let neg_b = self.negate_cell(b);
        let diff_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, diff_row, FieldElement::ONE);
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: diff_row,
            },
            FieldElement::ONE,
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
            .set(self.col_s_arith, inv_row, FieldElement::ONE);
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
        let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE));
        let neg_dti = self.negate_cell(diff_times_inv);
        let eq_row = self.alloc_row();
        self.system.set(self.col_s_arith, eq_row, FieldElement::ONE);
        self.constrain_constant(
            CellRef {
                column: self.col_b,
                row: eq_row,
            },
            FieldElement::ONE,
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
            .set(self.col_s_arith, enforce_row, FieldElement::ONE);
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
            FieldElement::ONE,
        );

        // CONSTRAINT 2: diff * eq = 0
        // d=0 is copy-constrained to fixed column so the gate constrains diff*eq = 0.
        let check_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, check_row, FieldElement::ONE);
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

        eq_cell
    }

    // ========================================================================
    // N-bit range enforcement
    // ========================================================================

    /// Enforce that `cell` holds a value in [0, 2^num_bits).
    /// Decomposes into `num_bits` boolean-enforced bits and checks sum == cell.
    fn enforce_n_range(&mut self, cell: CellRef, num_bits: u32) {
        if num_bits == 0 {
            // [0, 2^0) = {0}: the only valid value is zero.
            self.constrain_zero(cell);
            return;
        }

        let mut running_sum: Option<CellRef> = None;

        for i in 0..num_bits {
            let coeff = compute_power_of_two(i);
            let acc_row = self.alloc_row();
            self.system
                .set(self.col_s_arith, acc_row, FieldElement::ONE);
            let bit_cell = CellRef {
                column: self.col_a,
                row: acc_row,
            };
            self.witness_ops.push(PlonkWitnessOp::BitExtract {
                target: bit_cell,
                source: cell,
                bit_index: i,
            });
            self.constrain_constant(
                CellRef {
                    column: self.col_b,
                    row: acc_row,
                },
                coeff,
            );
            if let Some(prev) = running_sum {
                self.wire(
                    prev,
                    CellRef {
                        column: self.col_c,
                        row: acc_row,
                    },
                );
            } else {
                // First iteration: constrain col_c to zero so bit*coeff + 0 = sum
                self.constrain_zero(CellRef {
                    column: self.col_c,
                    row: acc_row,
                });
            }
            self.witness_ops
                .push(PlonkWitnessOp::ArithRow { row: acc_row });
            running_sum = Some(CellRef {
                column: self.col_d,
                row: acc_row,
            });
            self.emit_bool_check(bit_cell);
        }
        // Enforce sum == cell
        self.system.add_copy(running_sum.unwrap(), cell);
    }

    /// Enforce that `cell` holds a value in [0, 2^252).
    fn enforce_252_range(&mut self, cell: CellRef) {
        self.enforce_n_range(cell, 252);
    }

    // ========================================================================
    // IsLt gadget: n-bit decomposition
    // ========================================================================

    /// Returns a cell that is 1 if a < b, 0 otherwise.
    /// When `bound_bits` is Some(k), both operands are assumed to be in [0, 2^k)
    /// (from prior RangeCheck), so range checks are skipped and decomposition
    /// uses k+1 bits. Otherwise, full 252-bit range checks + 253-bit decomp.
    pub(super) fn emit_is_lt_bounded(
        &mut self,
        a: CellRef,
        b: CellRef,
        bound_bits: Option<u32>,
    ) -> CellRef {
        let effective_bits = bound_bits.unwrap_or_else(|| {
            self.enforce_252_range(a);
            self.enforce_252_range(b);
            252
        });
        let num_bits = effective_bits + 1;
        let offset = compute_power_of_two(effective_bits).sub(&FieldElement::ONE);

        // diff = b - a + offset
        let diff_val = PlonkVal::DeferredAdd(
            Box::new(PlonkVal::DeferredSub(
                Box::new(PlonkVal::Cell(b)),
                Box::new(PlonkVal::Cell(a)),
            )),
            Box::new(PlonkVal::Constant(offset)),
        );
        let diff_cell = self.materialize_val(&diff_val);

        // Decompose diff into num_bits bits with running sum accumulation
        let mut bit_cells = Vec::with_capacity(num_bits as usize);
        let mut running_sum: Option<CellRef> = None;

        for i in 0..num_bits {
            let coeff = compute_power_of_two(i);

            let acc_row = self.alloc_row();
            self.system
                .set(self.col_s_arith, acc_row, FieldElement::ONE);
            let bit_cell = CellRef {
                column: self.col_a,
                row: acc_row,
            };
            self.witness_ops.push(PlonkWitnessOp::BitExtract {
                target: bit_cell,
                source: diff_cell,
                bit_index: i,
            });
            self.constrain_constant(
                CellRef {
                    column: self.col_b,
                    row: acc_row,
                },
                coeff,
            );
            if let Some(prev) = running_sum {
                self.wire(
                    prev,
                    CellRef {
                        column: self.col_c,
                        row: acc_row,
                    },
                );
            } else {
                // First iteration: constrain col_c to zero so bit*coeff + 0 = sum
                self.constrain_zero(CellRef {
                    column: self.col_c,
                    row: acc_row,
                });
            }
            self.witness_ops
                .push(PlonkWitnessOp::ArithRow { row: acc_row });
            running_sum = Some(CellRef {
                column: self.col_d,
                row: acc_row,
            });
            bit_cells.push(bit_cell);

            // Boolean enforcement: bit^2 = bit
            self.emit_bool_check(bit_cell);
        }

        // Enforce sum == diff
        self.system.add_copy(running_sum.unwrap(), diff_cell);

        // Top bit is the result
        bit_cells[effective_bits as usize]
    }

    // ========================================================================
    // Range check: 1 lookup row
    // ========================================================================

    /// Maximum bits allowed for a range table lookup.
    /// 2^16 = 65536 rows is a reasonable ceiling; larger values should use
    /// bit-decomposition (like the R1CS backend does).
    const MAX_RANGE_TABLE_BITS: u32 = 16;

    pub(super) fn emit_range_check(
        &mut self,
        operand: CellRef,
        bits: u32,
    ) -> Result<(), PlonkishError> {
        self.ensure_range_table(bits)?;

        let row = self.alloc_row();
        let sel_col = self.range_selectors[&bits];
        self.system.set(sel_col, row, FieldElement::ONE);
        self.wire(
            operand,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        Ok(())
    }

    fn ensure_range_table(&mut self, bits: u32) -> Result<(), PlonkishError> {
        if self.range_tables.contains_key(&bits) {
            return Ok(());
        }

        if bits > Self::MAX_RANGE_TABLE_BITS {
            return Err(PlonkishError::MissingInput(format!(
                "range_check bits={bits} exceeds maximum of {} (table would have 2^{bits} rows)",
                Self::MAX_RANGE_TABLE_BITS,
            )));
        }

        let table_col = self.system.alloc_fixed();
        let table_size = 1usize << bits;

        if table_size > self.system.num_rows {
            self.system.num_rows = table_size;
            self.system.assignments.ensure_rows(table_size);
        }

        let mut values = Vec::with_capacity(table_size);
        for i in 0..table_size {
            let val = FieldElement::from_u64(i as u64);
            self.system.set(table_col, i, val);
            values.push(val);
        }

        self.system.lookup_tables.push(LookupTable {
            name: format!("range_{bits}"),
            column: table_col,
            values,
        });

        // Each bit-width gets its own dedicated selector column so that
        // enabling a 16-bit range check does not activate the 8-bit lookup.
        let sel_col = self.system.alloc_fixed();
        self.range_selectors.insert(bits, sel_col);

        self.system.register_lookup_with_selector(
            &format!("range_{bits}"),
            Expression::cell(sel_col, 0),
            vec![Expression::cell(self.col_a, 0)],
            vec![Expression::cell(table_col, 0)],
        );

        let idx = self.system.lookup_tables.len() - 1;
        self.range_tables.insert(bits, idx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_n_range_zero_bits_does_not_panic() {
        let mut compiler = PlonkishCompiler::new();
        // Allocate a cell with value zero
        let cell = compiler.materialize_val(&PlonkVal::Constant(FieldElement::ZERO));
        // Must not panic — constrains cell == 0
        compiler.enforce_n_range(cell, 0);
    }
}
