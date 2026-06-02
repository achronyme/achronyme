use super::*;

// ============================================================================
// Atoms
// ============================================================================

#[test]
fn lower_number_constant() {
    let insts = lower("42", &[], &[]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Const { .. })), 1);
    if let Instruction::Const { value, .. } = &insts.last().unwrap() {
        assert_eq!(*value, FieldElement::from_u64(42));
    } else {
        panic!("expected Const");
    }
}

#[test]
fn lower_negative_number() {
    let insts = lower("-5", &[], &[]);
    // Should produce Const(5) + Neg
    assert!(count(&insts, |i| matches!(i, Instruction::Const { .. })) >= 1);
    assert!(count(&insts, |i| matches!(i, Instruction::Neg { .. })) >= 1);
}

#[test]
fn lower_large_integer_literal() {
    // Value > u64::MAX: 2^64 = 18446744073709551616
    let insts = lower("18446744073709551616", &[], &[]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Const { .. })), 1);
    if let Instruction::Const { value, .. } = &insts[0] {
        // 2^64 in canonical form: limbs[1] = 1, limbs[0] = 0
        let canonical = value.to_canonical();
        assert_eq!(canonical[0], 0);
        assert_eq!(canonical[1], 1);
    } else {
        panic!("expected Const for large literal");
    }
}

#[test]
fn lower_very_large_integer_literal() {
    // Value near field size: p - 1 (largest valid field element)
    // p-1 = 21888242871839275222246405745257275088548364400416034343698204186575808495616
    let big = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    let insts = lower(big, &[], &[]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Const { .. })), 1);
    if let Instruction::Const { value, .. } = &insts[0] {
        assert!(!value.is_zero(), "p-1 should not be zero");
        // p-1 + 1 = p ≡ 0 (mod p)
        let one = FieldElement::ONE;
        assert!(value.add(&one).is_zero(), "p-1 + 1 should be 0 mod p");
    } else {
        panic!("expected Const for large literal");
    }
}

#[test]
fn lower_identifier_lookup() {
    let insts = lower("x", &["x"], &[]);
    // Just the Input instruction for x, no extra instructions for the lookup
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Input { .. })), 1);
}

// ============================================================================
// Binary operations
// ============================================================================

#[test]
fn lower_addition() {
    let insts = lower("x + y", &["x"], &["y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
}

#[test]
fn lower_subtraction() {
    let insts = lower("x - y", &["x"], &["y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Sub { .. })), 1);
}

#[test]
fn lower_multiplication() {
    let insts = lower("x * y", &["x"], &["y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mul { .. })), 1);
}

#[test]
fn lower_division() {
    let insts = lower("x / y", &["x"], &["y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Div { .. })), 1);
}

#[test]
fn lower_complex_expression() {
    // x * y + z
    let insts = lower("x * y + z", &[], &["x", "y", "z"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mul { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
}

// ============================================================================
// Prefix
// ============================================================================

#[test]
fn lower_negation() {
    let insts = lower("-x", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Neg { .. })), 1);
}

#[test]
fn lower_double_negation() {
    let insts = lower("--x", &[], &["x"]);
    // Double negation cancels out — no Neg instruction
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Neg { .. })), 0);
}

// ============================================================================
// Power
// ============================================================================

#[test]
fn lower_power() {
    let insts = lower("x ^ 3", &[], &["x"]);
    // x^3 = x * x * x → square-and-multiply: x^2 (mul), x^2 * x (mul) = 2 muls
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mul { .. })), 2);
}

#[test]
fn lower_power_zero() {
    let insts = lower("x ^ 0", &[], &["x"]);
    // x^0 = 1 → Const(1)
    let last = insts.last().unwrap();
    assert!(matches!(last, Instruction::Const { value, .. } if *value == FieldElement::ONE));
}

// ============================================================================
// Let bindings (aliasing)
// ============================================================================

#[test]
fn lower_let_alias() {
    // let y = x; y + y
    // `let` doesn't emit an instruction — y is an alias for x
    let insts = lower("let y = x\ny + y", &[], &["x"]);
    // 1 Input(x) + 1 Add(y+y)
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Input { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
    // The Add should reference x's var for both operands
    if let Instruction::Add { lhs, rhs, .. } = &insts[1] {
        assert_eq!(
            lhs, rhs,
            "let should alias, both operands should be the same SsaVar"
        );
    }
}

#[test]
fn lower_let_expression() {
    // let y = x * 2; y + 1
    let insts = lower("let y = x * 2\ny + 1", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mul { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
}
