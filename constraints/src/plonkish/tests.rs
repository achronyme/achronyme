use super::*;
use memory::FieldElement;

#[test]
fn test_column_allocation() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    sys.set(a, 0, FieldElement::from_u64(42));
    assert_eq!(sys.get(a, 0), FieldElement::from_u64(42));
    assert_eq!(sys.get(a, 1), FieldElement::ZERO);
}

#[test]
fn test_expression_constant() {
    let sys: PlonkishSystem = PlonkishSystem::new(4);
    let expr = Expression::constant(FieldElement::from_u64(7));
    assert_eq!(
        expr.evaluate(&sys.assignments, 0).unwrap(),
        FieldElement::from_u64(7)
    );
}

#[test]
fn test_expression_cell() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    sys.set(a, 2, FieldElement::from_u64(99));
    let expr = Expression::cell(a, 0);
    assert_eq!(
        expr.evaluate(&sys.assignments, 2).unwrap(),
        FieldElement::from_u64(99)
    );
}

#[test]
fn test_expression_arithmetic() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    let b = sys.alloc_advice();
    sys.set(a, 0, FieldElement::from_u64(3));
    sys.set(b, 0, FieldElement::from_u64(5));
    // a + b = 8
    let sum = Expression::cell(a, 0).add(Expression::cell(b, 0));
    assert_eq!(
        sum.evaluate(&sys.assignments, 0).unwrap(),
        FieldElement::from_u64(8)
    );
    // a * b = 15
    let prod = Expression::cell(a, 0).mul(Expression::cell(b, 0));
    assert_eq!(
        prod.evaluate(&sys.assignments, 0).unwrap(),
        FieldElement::from_u64(15)
    );
}

#[test]
fn test_expression_sub_neg() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    sys.set(a, 0, FieldElement::from_u64(10));
    // -a
    let neg = Expression::cell(a, 0).neg();
    let val = neg.evaluate(&sys.assignments, 0).unwrap();
    // -10 + 10 = 0
    assert!(val.add(&FieldElement::from_u64(10)).is_zero());
}

#[test]
fn test_rotation_out_of_bounds_error() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    sys.set(a, 3, FieldElement::from_u64(42));
    // Rotation +1 at row 3 → row 4, out of bounds for 4-row system
    let expr = Expression::cell(a, 1);
    let result = expr.evaluate(&sys.assignments, 3);
    assert!(
        matches!(result, Err(PlonkishError::RotationOutOfBounds { .. })),
        "rotation out of bounds must return error, not silent zero"
    );
    // Negative rotation at row 0 → row -1, out of bounds
    let expr_neg = Expression::cell(a, -1);
    let result_neg = expr_neg.evaluate(&sys.assignments, 0);
    assert!(
        matches!(result_neg, Err(PlonkishError::RotationOutOfBounds { .. })),
        "negative rotation out of bounds must return error"
    );
}

#[test]
fn test_gate_satisfied() {
    // Gate: s * (a * b + c - d) = 0
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    let b = sys.alloc_advice();
    sys.set(a, 0, FieldElement::from_u64(42));
    sys.set(b, 1, FieldElement::from_u64(42));
    sys.add_copy(CellRef { column: a, row: 0 }, CellRef { column: b, row: 1 });
    assert!(sys.verify().is_ok());
}

#[test]
fn test_copy_constraint_fails() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
    let a = sys.alloc_advice();
    let b = sys.alloc_advice();
    sys.set(a, 0, FieldElement::from_u64(42));
    sys.set(b, 1, FieldElement::from_u64(99));
    sys.add_copy(CellRef { column: a, row: 0 }, CellRef { column: b, row: 1 });
    let err = sys.verify().unwrap_err();
    assert!(matches!(err, PlonkishError::CopyConstraintViolation { .. }));
}

#[test]
fn test_range_table() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(8);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let sys: PlonkishSystem = PlonkishSystem::new(4);
    assert!(sys.verify().is_ok());
}

#[test]
fn test_grow_rows() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(2);
    let a = sys.alloc_advice();
    sys.set(a, 5, FieldElement::from_u64(77));
    assert_eq!(sys.get(a, 5), FieldElement::from_u64(77));
    assert!(sys.num_rows >= 6);
}

#[test]
fn test_multiple_gates() {
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    assert!(
        sys.verify().is_ok(),
        "active row with value=0 should pass (0 is in table)"
    );
}

#[test]
fn test_lookup_with_selector_inactive_skipped() {
    // Selector=0, value=99 (NOT in table) → inactive, should be skipped
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
    assert!(
        sys.verify().is_ok(),
        "inactive row should be skipped regardless of value"
    );
}

#[test]
fn test_lookup_with_selector_active_invalid_fails() {
    // Selector=1, value=99 (NOT in table) → must fail
    let mut sys: PlonkishSystem = PlonkishSystem::new(4);
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
