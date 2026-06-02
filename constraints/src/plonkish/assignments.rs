use std::collections::HashMap;

use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::Column;

// ============================================================================
// Assignments (2D table)
// ============================================================================

pub struct Assignments<F: FieldBackend = Bn254Fr> {
    pub num_rows: usize,
    values: HashMap<Column, Vec<FieldElement<F>>>,
}

impl<F: FieldBackend> Assignments<F> {
    pub fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            values: HashMap::new(),
        }
    }

    pub fn init_column(&mut self, col: Column, num_rows: usize) {
        self.values
            .entry(col)
            .or_insert_with(|| vec![FieldElement::<F>::zero(); num_rows]);
    }

    pub fn set(&mut self, col: Column, row: usize, val: FieldElement<F>) {
        let col_vals = self
            .values
            .entry(col)
            .or_insert_with(|| vec![FieldElement::<F>::zero(); self.num_rows]);
        if row >= col_vals.len() {
            col_vals.resize(row + 1, FieldElement::<F>::zero());
        }
        col_vals[row] = val;
    }

    pub fn get(&self, col: Column, row: usize) -> FieldElement<F> {
        self.values
            .get(&col)
            .and_then(|v| v.get(row))
            .copied()
            .unwrap_or_else(FieldElement::<F>::zero)
    }

    /// Get the values for a column as a slice.
    pub fn column_values(&self, col: Column) -> Option<&[FieldElement<F>]> {
        self.values.get(&col).map(|v| v.as_slice())
    }

    /// Resize all columns to at least `num_rows` rows.
    pub fn ensure_rows(&mut self, num_rows: usize) {
        self.num_rows = self.num_rows.max(num_rows);
        for vals in self.values.values_mut() {
            if vals.len() < self.num_rows {
                vals.resize(self.num_rows, FieldElement::<F>::zero());
            }
        }
    }
}

// ============================================================================
