use constraints::plonkish::{CellRef, Expression, LookupTable, PlonkishError};
use memory::{FieldBackend, FieldElement};

use super::super::compiler::PlonkishCompiler;
use super::super::primitives::compute_power_of_two;
use super::super::types::{PlonkVal, PlonkWitnessOp};

impl<F: FieldBackend> PlonkishCompiler<F> {
    /// Enforce that `cell` holds a value in [0, 2^num_bits).
    /// Decomposes into `num_bits` boolean-enforced bits and checks sum == cell.
    pub(super) fn enforce_n_range(&mut self, cell: CellRef, num_bits: u32) {
        if num_bits == 0 {
            // [0, 2^0) = {0}: the only valid value is zero.
            self.constrain_zero(cell);
            return;
        }

        let mut running_sum: Option<CellRef> = None;

        for i in 0..num_bits {
            let coeff = compute_power_of_two::<F>(i);
            let acc_row = self.alloc_row();
            self.system
                .set(self.col_s_arith, acc_row, FieldElement::<F>::one());
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

    /// Returns a cell that is 1 if a < b, 0 otherwise.
    /// When `bound_bits` is Some(k), both operands are assumed to be in [0, 2^k)
    /// (from prior RangeCheck), so range checks are skipped and decomposition
    /// uses k+1 bits. Otherwise, full 252-bit range checks + 253-bit decomp.
    pub(in super::super) fn emit_is_lt_bounded(
        &mut self,
        a: CellRef,
        b: CellRef,
        bound_bits: Option<u32>,
    ) -> Result<CellRef, PlonkishError> {
        let effective_bits = bound_bits.unwrap_or_else(|| {
            self.enforce_252_range(a);
            self.enforce_252_range(b);
            252
        });
        let num_bits = effective_bits + 1;
        let offset = compute_power_of_two::<F>(effective_bits).sub(&FieldElement::<F>::one());

        // diff = b - a + offset
        let diff_val = PlonkVal::DeferredAdd(
            Box::new(PlonkVal::DeferredSub(
                Box::new(PlonkVal::Cell(b)),
                Box::new(PlonkVal::Cell(a)),
            )),
            Box::new(PlonkVal::Constant(offset)),
        );
        let diff_cell = self.materialize_val(&diff_val)?;

        // Decompose diff into num_bits bits with running sum accumulation
        let mut bit_cells = Vec::with_capacity(num_bits as usize);
        let mut running_sum: Option<CellRef> = None;

        for i in 0..num_bits {
            let coeff = compute_power_of_two::<F>(i);

            let acc_row = self.alloc_row();
            self.system
                .set(self.col_s_arith, acc_row, FieldElement::<F>::one());
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
        Ok(bit_cells[effective_bits as usize])
    }

    /// Maximum bits allowed for a range table lookup.
    /// 2^16 = 65536 rows is a reasonable ceiling; larger values should use
    /// bit-decomposition (like the R1CS backend does).
    const MAX_RANGE_TABLE_BITS: u32 = 16;

    pub(in super::super) fn emit_range_check(
        &mut self,
        operand: CellRef,
        bits: u32,
    ) -> Result<(), PlonkishError> {
        self.ensure_range_table(bits)?;

        let row = self.alloc_row();
        let sel_col = self.range_selectors[&bits];
        self.system.set(sel_col, row, FieldElement::<F>::one());
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
            let val = FieldElement::<F>::from_u64(i as u64);
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

    /// Decompose `operand` into `num_bits` individual bits (LSB first).
    /// Returns the CellRef for each bit (boolean-enforced).
    pub(in super::super) fn emit_decompose(
        &mut self,
        operand: CellRef,
        num_bits: u32,
    ) -> Result<Vec<CellRef>, PlonkishError> {
        let mut bit_cells = Vec::with_capacity(num_bits as usize);
        let mut running_sum: Option<CellRef> = None;

        for i in 0..num_bits {
            let coeff = compute_power_of_two::<F>(i);
            let acc_row = self.alloc_row();
            self.system
                .set(self.col_s_arith, acc_row, FieldElement::<F>::one());
            let bit_cell = CellRef {
                column: self.col_a,
                row: acc_row,
            };
            self.witness_ops.push(PlonkWitnessOp::BitExtract {
                target: bit_cell,
                source: operand,
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
            bit_cells.push(bit_cell);
        }
        // Enforce sum == operand
        if let Some(sum_cell) = running_sum {
            self.system.add_copy(sum_cell, operand);
        } else {
            // 0-bit decompose: operand must be zero
            self.constrain_zero(operand);
        }
        Ok(bit_cells)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::Bn254Fr;

    #[test]
    fn enforce_n_range_zero_bits_does_not_panic() {
        let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
        // Allocate a cell with value zero
        let cell = compiler
            .materialize_val(&PlonkVal::Constant(FieldElement::<Bn254Fr>::zero()))
            .unwrap();
        // Must not panic - constrains cell == 0
        compiler.enforce_n_range(cell, 0);
    }
}
