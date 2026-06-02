use std::collections::HashSet;

use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::{
    Assignments, CellRef, Column, ColumnKind, CopyConstraint, Expression, Gate, Lookup,
    LookupTable, PlonkishError,
};

// ============================================================================
// PlonkishSystem
// ============================================================================

pub struct PlonkishSystem<F: FieldBackend = Bn254Fr> {
    pub fixed_columns: Vec<Column>,
    pub advice_columns: Vec<Column>,
    pub instance_columns: Vec<Column>,
    pub gates: Vec<Gate<F>>,
    pub lookups: Vec<Lookup<F>>,
    pub copies: Vec<CopyConstraint>,
    pub assignments: Assignments<F>,
    pub num_rows: usize,
    pub lookup_tables: Vec<LookupTable<F>>,
    // Counters for column allocation
    next_fixed: usize,
    next_advice: usize,
    next_instance: usize,
}

impl<F: FieldBackend> PlonkishSystem<F> {
    pub fn new(initial_rows: usize) -> Self {
        Self {
            fixed_columns: Vec::new(),
            advice_columns: Vec::new(),
            instance_columns: Vec::new(),
            gates: Vec::new(),
            lookups: Vec::new(),
            copies: Vec::new(),
            assignments: Assignments::new(initial_rows),
            num_rows: initial_rows,
            lookup_tables: Vec::new(),
            next_fixed: 0,
            next_advice: 0,
            next_instance: 0,
        }
    }

    // --- Column allocation ---

    pub fn alloc_fixed(&mut self) -> Column {
        let col = Column {
            kind: ColumnKind::Fixed,
            index: self.next_fixed,
        };
        self.next_fixed += 1;
        self.fixed_columns.push(col);
        self.assignments.init_column(col, self.num_rows);
        col
    }

    pub fn alloc_advice(&mut self) -> Column {
        let col = Column {
            kind: ColumnKind::Advice,
            index: self.next_advice,
        };
        self.next_advice += 1;
        self.advice_columns.push(col);
        self.assignments.init_column(col, self.num_rows);
        col
    }

    pub fn alloc_instance(&mut self) -> Column {
        let col = Column {
            kind: ColumnKind::Instance,
            index: self.next_instance,
        };
        self.next_instance += 1;
        self.instance_columns.push(col);
        self.assignments.init_column(col, self.num_rows);
        col
    }

    // --- Gate registration ---

    pub fn register_gate(&mut self, name: &str, poly: Expression<F>) {
        self.gates.push(Gate {
            name: name.to_string(),
            poly,
        });
    }

    // --- Lookup registration ---

    /// Register a lookup without an explicit selector.
    ///
    /// Uses the **legacy heuristic**: rows where all input expressions evaluate
    /// to zero are silently skipped. Prefer [`register_lookup_with_selector`]
    /// for new code — it uses an explicit selector expression and correctly
    /// checks rows even when the input value is legitimately zero.
    pub fn register_lookup(
        &mut self,
        name: &str,
        input_exprs: Vec<Expression<F>>,
        table_exprs: Vec<Expression<F>>,
    ) {
        self.lookups.push(Lookup {
            name: name.to_string(),
            selector: None,
            input_exprs,
            table_exprs,
        });
    }

    /// Register a lookup with an explicit selector expression.
    ///
    /// A row is active when the selector evaluates to non-zero. This is the
    /// preferred API — it avoids the legacy all-zero-skip heuristic and
    /// correctly handles cases where an input is legitimately zero.
    pub fn register_lookup_with_selector(
        &mut self,
        name: &str,
        selector: Expression<F>,
        input_exprs: Vec<Expression<F>>,
        table_exprs: Vec<Expression<F>>,
    ) {
        self.lookups.push(Lookup {
            name: name.to_string(),
            selector: Some(selector),
            input_exprs,
            table_exprs,
        });
    }

    // --- Copy constraints ---

    pub fn add_copy(&mut self, left: CellRef, right: CellRef) {
        self.copies.push(CopyConstraint { left, right });
    }

    // --- Assignment helpers ---

    pub fn set(&mut self, col: Column, row: usize, val: FieldElement<F>) {
        if row >= self.num_rows {
            self.num_rows = row + 1;
            self.assignments.ensure_rows(self.num_rows);
        }
        self.assignments.set(col, row, val);
    }

    pub fn get(&self, col: Column, row: usize) -> FieldElement<F> {
        self.assignments.get(col, row)
    }

    // --- Verification ---

    pub fn verify(&self) -> Result<(), PlonkishError> {
        // 1. Gate check: for each gate, for each row, poly evaluates to 0
        for gate in &self.gates {
            for row in 0..self.num_rows {
                let val = gate.poly.evaluate(&self.assignments, row)?;
                if !val.is_zero() {
                    return Err(PlonkishError::GateNotSatisfied {
                        gate: gate.name.clone(),
                        row,
                    });
                }
            }
        }

        // 2. Copy check: left.value == right.value
        for copy in &self.copies {
            let left_val = self.assignments.get(copy.left.column, copy.left.row);
            let right_val = self.assignments.get(copy.right.column, copy.right.row);
            if left_val != right_val {
                return Err(PlonkishError::CopyConstraintViolation {
                    left: copy.left,
                    right: copy.right,
                });
            }
        }

        // 3. Lookup check: for each lookup, for each active row, the input
        //    tuple must appear in the table columns.
        for lookup in &self.lookups {
            // Build the set of table tuples — O(N) with HashSet for O(1) membership.
            let mut table_set: HashSet<Vec<FieldElement<F>>> = HashSet::new();
            for row in 0..self.num_rows {
                let tuple: Vec<FieldElement<F>> = lookup
                    .table_exprs
                    .iter()
                    .map(|e| e.evaluate(&self.assignments, row))
                    .collect::<Result<Vec<_>, _>>()?;
                table_set.insert(tuple);
            }

            for row in 0..self.num_rows {
                // Determine row activity via explicit selector or legacy heuristic
                if let Some(sel) = &lookup.selector {
                    if sel.evaluate(&self.assignments, row)?.is_zero() {
                        continue; // row inactive per selector
                    }
                }

                let input: Vec<FieldElement<F>> = lookup
                    .input_exprs
                    .iter()
                    .map(|e| e.evaluate(&self.assignments, row))
                    .collect::<Result<Vec<_>, _>>()?;

                // Legacy fallback: no selector → skip all-zero inputs (backward compat)
                if lookup.selector.is_none() && input.iter().all(|v| v.is_zero()) {
                    continue;
                }

                if !table_set.contains(&input) {
                    return Err(PlonkishError::LookupFailed {
                        lookup: lookup.name.clone(),
                        row,
                    });
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
