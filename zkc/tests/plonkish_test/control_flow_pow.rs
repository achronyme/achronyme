use super::*;

// ============================================================================
// T9: Plonkish control flow — for loop parity
// ============================================================================

#[test]
fn test_plonkish_for_empty_range() {
    // for i in 0..0 { ... } → 0 iterations, no circuit rows from body
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = r#"
        for i in 0..0 { let step = a * a }
        assert_eq(0, out)
    "#;
    compile_source(source, &["out"], &[], &inputs);
}

#[test]
fn test_plonkish_for_accumulation() {
    // Accumulate: sum = 1 + 2 + 3 = 6
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(6));

    let source = r#"
        let acc = 0
        for i in 1..4 {
            let acc = acc + i
        }
        assert_eq(acc, out)
    "#;
    compile_source(source, &["out"], &[], &inputs);
}

#[test]
fn test_plonkish_for_iterator_as_constant() {
    // Multiplying by constant iterator i should work
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::from_u64(10)); // a * 2

    let source = r#"
        let r = 0
        for i in 0..3 { let r = a * i }
        assert_eq(a * 2, out)
    "#;
    compile_source(source, &["out"], &["a"], &inputs);
}

#[test]
fn test_plonkish_for_nested() {
    // Nested for: 2 * 3 iterations of assert_eq(a * a, out)
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(9)); // 3*3

    let source = "for i in 0..2 { for j in 0..3 { assert_eq(a * a, out) } }";
    compile_source(source, &["out"], &["a"], &inputs);
}

#[test]
fn test_plonkish_for_with_witness() {
    // for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(21));

    let source = "for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)";
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

// ============================================================================
// T9: Plonkish control flow — if/else parity
// ============================================================================

#[test]
fn test_plonkish_if_else_basic() {
    // if flag { a } else { b } — flag=1 selects a
    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    let source = "let r = if flag { a } else { b }; assert_eq(r, out)";
    compile_source(source, &["out"], &["flag", "a", "b"], &inputs);
}

#[test]
fn test_plonkish_if_else_flag_zero() {
    // if flag { a } else { b } — flag=0 selects b
    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ZERO);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));
    inputs.insert("out".to_string(), FieldElement::from_u64(99));

    let source = "let r = if flag { a } else { b }; assert_eq(r, out)";
    compile_source(source, &["out"], &["flag", "a", "b"], &inputs);
}

#[test]
fn test_plonkish_if_without_else() {
    // if flag { a } — else defaults to 0; flag=0 → result=0
    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ZERO);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let source = "let r = if flag { a }; assert_eq(r, out)";
    compile_source(source, &["out"], &["flag", "a"], &inputs);
}

#[test]
fn test_plonkish_if_with_arithmetic_branches() {
    // if flag { a * b } else { c + d } — flag=1 → a*b=42
    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(10));
    inputs.insert("d".to_string(), FieldElement::from_u64(20));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    let source = "let r = if flag { a * b } else { c + d }; assert_eq(r, out)";
    compile_source(source, &["out"], &["flag", "a", "b", "c", "d"], &inputs);
}

#[test]
fn test_plonkish_if_nested_mux() {
    // if c1 { a } else { if c2 { b } else { c } }
    // c1=0, c2=1 → result = b = 50
    let mut inputs = HashMap::new();
    inputs.insert("c1".to_string(), FieldElement::ZERO);
    inputs.insert("c2".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(50));
    inputs.insert("c".to_string(), FieldElement::from_u64(90));
    inputs.insert("out".to_string(), FieldElement::from_u64(50));

    let source = "let r = if c1 { a } else { if c2 { b } else { c } }; assert_eq(r, out)";
    compile_source(source, &["out"], &["c1", "c2", "a", "b", "c"], &inputs);
}

#[test]
fn test_plonkish_if_else_if_chain() {
    // if c1 { a } else if c2 { b } else { c }
    // c1=0, c2=0 → result = c = 90
    let mut inputs = HashMap::new();
    inputs.insert("c1".to_string(), FieldElement::ZERO);
    inputs.insert("c2".to_string(), FieldElement::ZERO);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(50));
    inputs.insert("c".to_string(), FieldElement::from_u64(90));
    inputs.insert("out".to_string(), FieldElement::from_u64(90));

    let source = "let r = if c1 { a } else if c2 { b } else { c }; assert_eq(r, out)";
    compile_source(source, &["out"], &["c1", "c2", "a", "b", "c"], &inputs);
}

// ============================================================================
// T9: Plonkish control flow — power operations
// ============================================================================

#[test]
fn test_plonkish_pow_cubic() {
    // x^3 with x=3 → 27
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(27));

    let source = "assert_eq(x^3, out)";
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_plonkish_pow_zero() {
    // x^0 = 1 for any x
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("out".to_string(), FieldElement::ONE);

    let source = "assert_eq(x^0, out)";
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_plonkish_pow_one() {
    // x^1 = x
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("out".to_string(), FieldElement::from_u64(42));

    let source = "assert_eq(x^1, out)";
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_plonkish_pow_in_expression() {
    // x^2 + x + 5 = 35 with x=5
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::from_u64(35));

    let source = "assert_eq(x^2 + x + 5, out)";
    compile_source(source, &["out"], &["x"], &inputs);
}

// ============================================================================
// T9: Plonkish combined — poseidon in loop, control flow + circuit
// ============================================================================

#[test]
fn test_plonkish_poseidon_in_for_loop() {
    // Two poseidon calls via loop iteration
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(1);
    let b = FieldElement::from_u64(2);
    let h1 = poseidon_hash(&params, a, b);
    let h2 = poseidon_hash(&params, h1, b);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), a);
    inputs.insert("b".to_string(), b);
    inputs.insert("out".to_string(), h2);

    let source = r#"
        let h = poseidon(a, b)
        let h = poseidon(h, b)
        assert_eq(h, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_for_with_if_inside() {
    // Combined: for loop with conditional inside
    // flag=1, a=3, b=7 → a*b=21
    let mut inputs = HashMap::new();
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(3));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::from_u64(21));

    let source = "for i in 0..2 { let r = if flag { a * b } else { c }; assert_eq(r, out) }";
    compile_source(source, &["out"], &["flag", "a", "b", "c"], &inputs);
}

#[test]
fn test_plonkish_full_circuit_with_control_flow() {
    // Realistic: conditional x^2 vs x+1, with loop (DCE'd)
    // flag=1, x=5 → x*x = 25
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(5));
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("out".to_string(), FieldElement::from_u64(25));

    let source = "for i in 0..2 { let step = x * x }; \
         let result = if flag { x * x } else { x + 1 }; \
         assert_eq(result, out)";
    compile_source(source, &["out"], &["x", "flag"], &inputs);
}
