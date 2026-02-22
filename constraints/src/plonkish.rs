/// Plonkish Constraint System
///
/// A Plonkish system represents computation using:
/// - **Arithmetic gates**: s_arith * (a * b + c - d) = 0
/// - **Lookup tables**: proving a value belongs to a precomputed table
/// - **Copy constraints**: enforcing equality between cells
///
/// This provides more efficient circuits than R1CS for many operations,
/// especially range checks (O(1) lookup vs O(bits) boolean decomposition).

use std::collections::HashMap;
use std::fmt;

use memory::FieldElement;

// ============================================================================
// Column types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnKind {
    Fixed,
    Advice,
    Instance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Column {
    pub kind: ColumnKind,
    pub index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellRef {
    pub column: Column,
    pub row: usize,
}

// ============================================================================
// Expression (recursive symbolic polynomials)
// ============================================================================

#[derive(Debug, Clone)]
pub enum Expression {
    Constant(FieldElement),
    Cell(Column, i32), // column, rotation offset (0 = current row)
    Neg(Box<Expression>),
    Sum(Box<Expression>, Box<Expression>),
    Product(Box<Expression>, Box<Expression>),
}

impl Expression {
    pub fn constant(val: FieldElement) -> Self {
        Expression::Constant(val)
    }

    pub fn cell(col: Column, rotation: i32) -> Self {
        Expression::Cell(col, rotation)
    }

    pub fn add(self, other: Self) -> Self {
        Expression::Sum(Box::new(self), Box::new(other))
    }

    pub fn mul(self, other: Self) -> Self {
        Expression::Product(Box::new(self), Box::new(other))
    }

    pub fn sub(self, other: Self) -> Self {
        Expression::Sum(Box::new(self), Box::new(Expression::Neg(Box::new(other))))
    }

    pub fn neg(self) -> Self {
        Expression::Neg(Box::new(self))
    }

    /// Evaluate this expression at a given row using the assignments table.
    pub fn evaluate(&self, assignments: &Assignments, row: usize) -> FieldElement {
        match self {
            Expression::Constant(val) => *val,
            Expression::Cell(col, rotation) => {
                let actual = row as i64 + *rotation as i64;
                if actual < 0 || actual as usize >= assignments.num_rows {
                    FieldElement::ZERO
                } else {
                    assignments.get(*col, actual as usize)
                }
            }
            Expression::Neg(inner) => inner.evaluate(assignments, row).neg(),
            Expression::Sum(a, b) => {
                let av = a.evaluate(assignments, row);
                let bv = b.evaluate(assignments, row);
                av.add(&bv)
            }
            Expression::Product(a, b) => {
                let av = a.evaluate(assignments, row);
                let bv = b.evaluate(assignments, row);
                av.mul(&bv)
            }
        }
    }
}

// ============================================================================
// Gate, Lookup, CopyConstraint
// ============================================================================

pub struct Gate {
    pub name: String,
    pub poly: Expression,
}

pub struct Lookup {
    pub name: String,
    /// Optional selector expression: when present, only rows where this evaluates
    /// to non-zero are checked. When absent, falls back to the legacy all-zero skip.
    pub selector: Option<Expression>,
    pub input_exprs: Vec<Expression>,
    pub table_exprs: Vec<Expression>,
}

/// A precomputed lookup table stored as a set of value tuples.
pub struct LookupTable {
    pub name: String,
    pub column: Column,
    pub values: Vec<FieldElement>,
}

pub struct CopyConstraint {
    pub left: CellRef,
    pub right: CellRef,
}

// ============================================================================
// Assignments (2D table)
// ============================================================================

pub struct Assignments {
    pub num_rows: usize,
    values: HashMap<Column, Vec<FieldElement>>,
}

impl Assignments {
    pub fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            values: HashMap::new(),
        }
    }

    pub fn init_column(&mut self, col: Column, num_rows: usize) {
        self.values
            .entry(col)
            .or_insert_with(|| vec![FieldElement::ZERO; num_rows]);
    }

    pub fn set(&mut self, col: Column, row: usize, val: FieldElement) {
        let col_vals = self.values.entry(col).or_insert_with(|| {
            vec![FieldElement::ZERO; self.num_rows]
        });
        if row >= col_vals.len() {
            col_vals.resize(row + 1, FieldElement::ZERO);
        }
        col_vals[row] = val;
    }

    pub fn get(&self, col: Column, row: usize) -> FieldElement {
        self.values
            .get(&col)
            .and_then(|v| v.get(row))
            .copied()
            .unwrap_or(FieldElement::ZERO)
    }

    /// Get the values for a column as a slice.
    pub fn column_values(&self, col: Column) -> Option<&[FieldElement]> {
        self.values.get(&col).map(|v| v.as_slice())
    }

    /// Resize all columns to at least `num_rows` rows.
    pub fn ensure_rows(&mut self, num_rows: usize) {
        self.num_rows = self.num_rows.max(num_rows);
        for vals in self.values.values_mut() {
            if vals.len() < self.num_rows {
                vals.resize(self.num_rows, FieldElement::ZERO);
            }
        }
    }
}

// ============================================================================
// PlonkishError
// ============================================================================

#[derive(Debug)]
pub enum PlonkishError {
    GateNotSatisfied { gate: String, row: usize },
    CopyConstraintViolation { left: CellRef, right: CellRef },
    LookupFailed { lookup: String, row: usize },
    MissingInput(String),
}

impl fmt::Display for PlonkishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlonkishError::GateNotSatisfied { gate, row } => {
                write!(f, "gate `{gate}` not satisfied at row {row}")
            }
            PlonkishError::CopyConstraintViolation { left, right } => {
                write!(
                    f,
                    "copy constraint violated: ({:?}, row {}) != ({:?}, row {})",
                    left.column, left.row, right.column, right.row
                )
            }
            PlonkishError::LookupFailed { lookup, row } => {
                write!(f, "lookup `{lookup}` failed at row {row}")
            }
            PlonkishError::MissingInput(name) => {
                write!(f, "missing input for variable `{name}`")
            }
        }
    }
}

impl std::error::Error for PlonkishError {}

// ============================================================================
// PlonkishSystem
// ============================================================================

pub struct PlonkishSystem {
    pub fixed_columns: Vec<Column>,
    pub advice_columns: Vec<Column>,
    pub instance_columns: Vec<Column>,
    pub gates: Vec<Gate>,
    pub lookups: Vec<Lookup>,
    pub copies: Vec<CopyConstraint>,
    pub assignments: Assignments,
    pub num_rows: usize,
    pub lookup_tables: Vec<LookupTable>,
    // Counters for column allocation
    next_fixed: usize,
    next_advice: usize,
    next_instance: usize,
}

impl PlonkishSystem {
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

    pub fn register_gate(&mut self, name: &str, poly: Expression) {
        self.gates.push(Gate {
            name: name.to_string(),
            poly,
        });
    }

    // --- Lookup registration ---

    pub fn register_lookup(
        &mut self,
        name: &str,
        input_exprs: Vec<Expression>,
        table_exprs: Vec<Expression>,
    ) {
        self.lookups.push(Lookup {
            name: name.to_string(),
            selector: None,
            input_exprs,
            table_exprs,
        });
    }

    pub fn register_lookup_with_selector(
        &mut self,
        name: &str,
        selector: Expression,
        input_exprs: Vec<Expression>,
        table_exprs: Vec<Expression>,
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

    pub fn set(&mut self, col: Column, row: usize, val: FieldElement) {
        if row >= self.num_rows {
            self.num_rows = row + 1;
            self.assignments.ensure_rows(self.num_rows);
        }
        self.assignments.set(col, row, val);
    }

    pub fn get(&self, col: Column, row: usize) -> FieldElement {
        self.assignments.get(col, row)
    }

    // --- Verification ---

    pub fn verify(&self) -> Result<(), PlonkishError> {
        // 1. Gate check: for each gate, for each row, poly evaluates to 0
        for gate in &self.gates {
            for row in 0..self.num_rows {
                let val = gate.poly.evaluate(&self.assignments, row);
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
            // Build the set of table tuples
            let mut table_set: Vec<Vec<FieldElement>> = Vec::new();
            for row in 0..self.num_rows {
                let tuple: Vec<FieldElement> = lookup
                    .table_exprs
                    .iter()
                    .map(|e| e.evaluate(&self.assignments, row))
                    .collect();
                table_set.push(tuple);
            }

            for row in 0..self.num_rows {
                // Determine row activity via explicit selector or legacy heuristic
                if let Some(sel) = &lookup.selector {
                    if sel.evaluate(&self.assignments, row).is_zero() {
                        continue; // row inactive per selector
                    }
                }

                let input: Vec<FieldElement> = lookup
                    .input_exprs
                    .iter()
                    .map(|e| e.evaluate(&self.assignments, row))
                    .collect();

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
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use memory::FieldElement;

    #[test]
    fn test_column_allocation() {
        let mut sys = PlonkishSystem::new(4);
        let f0 = sys.alloc_fixed();
        let a0 = sys.alloc_advice();
        let i0 = sys.alloc_instance();
        assert_eq!(f0.kind, ColumnKind::Fixed);
        assert_eq!(f0.index, 0);
        assert_eq!(a0.kind, ColumnKind::Advice);
        assert_eq!(a0.index, 0);
        assert_eq!(i0.kind, ColumnKind::Instance);
        assert_eq!(i0.index, 0);
    }

    #[test]
    fn test_cell_assignment_and_get() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        sys.set(a, 0, FieldElement::from_u64(42));
        assert_eq!(sys.get(a, 0), FieldElement::from_u64(42));
        assert_eq!(sys.get(a, 1), FieldElement::ZERO);
    }

    #[test]
    fn test_expression_constant() {
        let sys = PlonkishSystem::new(4);
        let expr = Expression::constant(FieldElement::from_u64(7));
        assert_eq!(
            expr.evaluate(&sys.assignments, 0),
            FieldElement::from_u64(7)
        );
    }

    #[test]
    fn test_expression_cell() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        sys.set(a, 2, FieldElement::from_u64(99));
        let expr = Expression::cell(a, 0);
        assert_eq!(
            expr.evaluate(&sys.assignments, 2),
            FieldElement::from_u64(99)
        );
    }

    #[test]
    fn test_expression_arithmetic() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        sys.set(a, 0, FieldElement::from_u64(3));
        sys.set(b, 0, FieldElement::from_u64(5));
        // a + b = 8
        let sum = Expression::cell(a, 0).add(Expression::cell(b, 0));
        assert_eq!(
            sum.evaluate(&sys.assignments, 0),
            FieldElement::from_u64(8)
        );
        // a * b = 15
        let prod = Expression::cell(a, 0).mul(Expression::cell(b, 0));
        assert_eq!(
            prod.evaluate(&sys.assignments, 0),
            FieldElement::from_u64(15)
        );
    }

    #[test]
    fn test_expression_sub_neg() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        sys.set(a, 0, FieldElement::from_u64(10));
        // -a
        let neg = Expression::cell(a, 0).neg();
        let val = neg.evaluate(&sys.assignments, 0);
        // -10 + 10 = 0
        assert!(val.add(&FieldElement::from_u64(10)).is_zero());
    }

    #[test]
    fn test_gate_satisfied() {
        // Gate: s * (a * b + c - d) = 0
        let mut sys = PlonkishSystem::new(4);
        let s = sys.alloc_fixed();
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        let c = sys.alloc_advice();
        let d = sys.alloc_advice();

        // Row 0: s=1, a=3, b=4, c=5, d=17 → 3*4+5=17 ✓
        sys.set(s, 0, FieldElement::ONE);
        sys.set(a, 0, FieldElement::from_u64(3));
        sys.set(b, 0, FieldElement::from_u64(4));
        sys.set(c, 0, FieldElement::from_u64(5));
        sys.set(d, 0, FieldElement::from_u64(17));

        // Row 1: s=0 (inactive)

        let poly = Expression::cell(s, 0).mul(
            Expression::cell(a, 0)
                .mul(Expression::cell(b, 0))
                .add(Expression::cell(c, 0))
                .sub(Expression::cell(d, 0)),
        );
        sys.register_gate("arith", poly);
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_gate_not_satisfied() {
        let mut sys = PlonkishSystem::new(4);
        let s = sys.alloc_fixed();
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        let c = sys.alloc_advice();
        let d = sys.alloc_advice();

        // Row 0: s=1, a=3, b=4, c=5, d=99 → 3*4+5=17 ≠ 99
        sys.set(s, 0, FieldElement::ONE);
        sys.set(a, 0, FieldElement::from_u64(3));
        sys.set(b, 0, FieldElement::from_u64(4));
        sys.set(c, 0, FieldElement::from_u64(5));
        sys.set(d, 0, FieldElement::from_u64(99));

        let poly = Expression::cell(s, 0).mul(
            Expression::cell(a, 0)
                .mul(Expression::cell(b, 0))
                .add(Expression::cell(c, 0))
                .sub(Expression::cell(d, 0)),
        );
        sys.register_gate("arith", poly);
        assert!(sys.verify().is_err());
    }

    #[test]
    fn test_copy_constraint_ok() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        sys.set(a, 0, FieldElement::from_u64(42));
        sys.set(b, 1, FieldElement::from_u64(42));
        sys.add_copy(
            CellRef { column: a, row: 0 },
            CellRef { column: b, row: 1 },
        );
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_copy_constraint_fails() {
        let mut sys = PlonkishSystem::new(4);
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        sys.set(a, 0, FieldElement::from_u64(42));
        sys.set(b, 1, FieldElement::from_u64(99));
        sys.add_copy(
            CellRef { column: a, row: 0 },
            CellRef { column: b, row: 1 },
        );
        let err = sys.verify().unwrap_err();
        assert!(matches!(err, PlonkishError::CopyConstraintViolation { .. }));
    }

    #[test]
    fn test_range_table() {
        let mut sys = PlonkishSystem::new(8);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();
        let selector = sys.alloc_fixed();

        // Fill table: values 0..8 in table_col
        for i in 0..8u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }

        // Row 0: selector=1, input=5 (valid, 5 ∈ 0..8)
        sys.set(selector, 0, FieldElement::ONE);
        sys.set(input_col, 0, FieldElement::from_u64(5));

        // Lookup: when selector active, input must be in table
        sys.register_lookup(
            "range",
            vec![Expression::cell(selector, 0).mul(Expression::cell(input_col, 0))],
            vec![Expression::cell(table_col, 0)],
        );
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_lookup_fails() {
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();

        // Table: 0, 1, 2, 3
        for i in 0..4u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }

        // Row 0: input=99 (not in table)
        sys.set(input_col, 0, FieldElement::from_u64(99));

        sys.register_lookup(
            "range",
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        let err = sys.verify().unwrap_err();
        assert!(matches!(err, PlonkishError::LookupFailed { .. }));
    }

    #[test]
    fn test_full_arithmetic_circuit() {
        // Circuit: prove a*b + c = d
        let mut sys = PlonkishSystem::new(4);
        let s_arith = sys.alloc_fixed();
        let a = sys.alloc_advice();
        let b = sys.alloc_advice();
        let c = sys.alloc_advice();
        let d = sys.alloc_advice();

        // Gate: s_arith * (a*b + c - d) = 0
        let poly = Expression::cell(s_arith, 0).mul(
            Expression::cell(a, 0)
                .mul(Expression::cell(b, 0))
                .add(Expression::cell(c, 0))
                .sub(Expression::cell(d, 0)),
        );
        sys.register_gate("arith", poly);

        // Row 0: 3*4+5=17
        sys.set(s_arith, 0, FieldElement::ONE);
        sys.set(a, 0, FieldElement::from_u64(3));
        sys.set(b, 0, FieldElement::from_u64(4));
        sys.set(c, 0, FieldElement::from_u64(5));
        sys.set(d, 0, FieldElement::from_u64(17));

        // Row 1: 6*7+0=42
        sys.set(s_arith, 1, FieldElement::ONE);
        sys.set(a, 1, FieldElement::from_u64(6));
        sys.set(b, 1, FieldElement::from_u64(7));
        sys.set(c, 1, FieldElement::ZERO);
        sys.set(d, 1, FieldElement::from_u64(42));

        // Rows 2,3: inactive (s_arith=0)
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_empty_system_verifies() {
        let sys = PlonkishSystem::new(4);
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_grow_rows() {
        let mut sys = PlonkishSystem::new(2);
        let a = sys.alloc_advice();
        sys.set(a, 5, FieldElement::from_u64(77));
        assert_eq!(sys.get(a, 5), FieldElement::from_u64(77));
        assert!(sys.num_rows >= 6);
    }

    #[test]
    fn test_multiple_gates() {
        let mut sys = PlonkishSystem::new(4);
        let s1 = sys.alloc_fixed();
        let s2 = sys.alloc_fixed();
        let a = sys.alloc_advice();

        // Gate 1: s1 * (a - 42) = 0  → when s1=1, a must be 42
        sys.register_gate(
            "g1",
            Expression::cell(s1, 0)
                .mul(Expression::cell(a, 0).sub(Expression::constant(FieldElement::from_u64(42)))),
        );
        // Gate 2: s2 * (a - 99) = 0  → when s2=1, a must be 99
        sys.register_gate(
            "g2",
            Expression::cell(s2, 0)
                .mul(Expression::cell(a, 0).sub(Expression::constant(FieldElement::from_u64(99)))),
        );

        // Row 0: s1=1, s2=0, a=42
        sys.set(s1, 0, FieldElement::ONE);
        sys.set(a, 0, FieldElement::from_u64(42));
        // Row 1: s1=0, s2=1, a=99
        sys.set(s2, 1, FieldElement::ONE);
        sys.set(a, 1, FieldElement::from_u64(99));
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_lookup_inactive_rows_pass() {
        // Lookup with all-zero inputs should be skipped (inactive)
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();

        // Table: 10, 20, 30, 40
        sys.set(table_col, 0, FieldElement::from_u64(10));
        sys.set(table_col, 1, FieldElement::from_u64(20));
        sys.set(table_col, 2, FieldElement::from_u64(30));
        sys.set(table_col, 3, FieldElement::from_u64(40));

        // All input rows = 0 (inactive)
        sys.register_lookup(
            "range",
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        assert!(sys.verify().is_ok());
    }

    // ================================================================
    // H5: Selector-based lookup tests
    // ================================================================

    #[test]
    fn test_lookup_with_selector_active_passes() {
        // Selector=1, value=5, 5 is in table → pass
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();
        let selector = sys.alloc_fixed();

        for i in 0..4u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }
        sys.set(selector, 0, FieldElement::ONE);
        sys.set(input_col, 0, FieldElement::from_u64(3));

        sys.register_lookup_with_selector(
            "range",
            Expression::cell(selector, 0),
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        assert!(sys.verify().is_ok());
    }

    #[test]
    fn test_lookup_with_selector_active_zero_value_passes() {
        // Selector=1, value=0, 0 is in table → must NOT be skipped, must pass
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();
        let selector = sys.alloc_fixed();

        for i in 0..4u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }
        sys.set(selector, 0, FieldElement::ONE);
        sys.set(input_col, 0, FieldElement::ZERO); // value=0, but row is active

        sys.register_lookup_with_selector(
            "range",
            Expression::cell(selector, 0),
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        assert!(sys.verify().is_ok(), "active row with value=0 should pass (0 is in table)");
    }

    #[test]
    fn test_lookup_with_selector_inactive_skipped() {
        // Selector=0, value=99 (NOT in table) → inactive, should be skipped
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();
        let selector = sys.alloc_fixed();

        for i in 0..4u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }
        // Row 0: selector=0 (inactive), input=99 (not in table)
        sys.set(selector, 0, FieldElement::ZERO);
        sys.set(input_col, 0, FieldElement::from_u64(99));

        sys.register_lookup_with_selector(
            "range",
            Expression::cell(selector, 0),
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        assert!(sys.verify().is_ok(), "inactive row should be skipped regardless of value");
    }

    #[test]
    fn test_lookup_with_selector_active_invalid_fails() {
        // Selector=1, value=99 (NOT in table) → must fail
        let mut sys = PlonkishSystem::new(4);
        let table_col = sys.alloc_fixed();
        let input_col = sys.alloc_advice();
        let selector = sys.alloc_fixed();

        for i in 0..4u64 {
            sys.set(table_col, i as usize, FieldElement::from_u64(i));
        }
        sys.set(selector, 0, FieldElement::ONE);
        sys.set(input_col, 0, FieldElement::from_u64(99));

        sys.register_lookup_with_selector(
            "range",
            Expression::cell(selector, 0),
            vec![Expression::cell(input_col, 0)],
            vec![Expression::cell(table_col, 0)],
        );
        let err = sys.verify().unwrap_err();
        assert!(matches!(err, PlonkishError::LookupFailed { .. }));
    }
}
