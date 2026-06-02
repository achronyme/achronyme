use super::*;

// ============================================================================
// IR-level circuit tests
// ============================================================================

#[test]
fn test_ir_simple_mul() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_ir_quadratic() {
    // x^2 + x + 5 = 35 → x = 5
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(35));
    inputs.insert("x".to_string(), FieldElement::from_u64(5));

    let source = r#"
        let y = x^2 + x + 5
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_for_unroll() {
    // Accumulate: sum = 1 + 2 + 3 + 4 = 10
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let acc = 0
        for i in 1..5 {
            let acc = acc + i
        }
        assert_eq(acc, out)
    "#;
    compile_source(source, &["out"], &[], &inputs);
}

#[test]
fn test_ir_negation() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let y = -(-x)
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_subtraction() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let r = x - y
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

// ============================================================================
// IsLt / IsLe tests
// ============================================================================

#[test]
fn test_is_lt_true() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_false() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(7));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_large_values() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(1_000_000));
    inputs.insert("b".to_string(), FieldElement::from_u64(9_999_999));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a < b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_le_strict_less() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(5));
    inputs.insert("b".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a <= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_le_false() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        let r = a <= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_gt_via_plonkish() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a > b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_ge_strict_greater() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = r#"
        let r = a >= b
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_is_lt_with_mux() {
    // Use comparison result in a MUX
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(100));

    let source = r#"
        let cmp = a < b
        let r = mux(cmp, 100, 200)
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}
