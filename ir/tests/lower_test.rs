use ir::{Instruction, IrLowering, Visibility};
use memory::FieldElement;

/// Helper: lower a circuit with given public/witness inputs.
fn lower(source: &str, public: &[&str], witness: &[&str]) -> Vec<Instruction> {
    IrLowering::lower_circuit(source, public, witness)
        .expect("lowering failed")
        .instructions
}

/// Count instructions of a specific type.
fn count<F>(insts: &[Instruction], pred: F) -> usize
where
    F: Fn(&Instruction) -> bool,
{
    insts.iter().filter(|i| pred(i)).count()
}

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
        assert_eq!(lhs, rhs, "let should alias, both operands should be the same SsaVar");
    }
}

#[test]
fn lower_let_expression() {
    // let y = x * 2; y + 1
    let insts = lower("let y = x * 2\ny + 1", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mul { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
}

// ============================================================================
// Builtins
// ============================================================================

#[test]
fn lower_assert_eq() {
    let insts = lower("assert_eq(x, y)", &["x"], &["y"]);
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::AssertEq { .. })),
        1
    );
}

#[test]
fn lower_poseidon() {
    let insts = lower("poseidon(x, y)", &[], &["x", "y"]);
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::PoseidonHash { .. })),
        1
    );
}

#[test]
fn lower_mux() {
    let insts = lower("mux(c, a, b)", &[], &["c", "a", "b"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mux { .. })), 1);
}

// ============================================================================
// Control flow
// ============================================================================

#[test]
fn lower_if_else() {
    let insts = lower("if c { x } else { y }", &[], &["c", "x", "y"]);
    // if/else → Mux
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mux { .. })), 1);
}

#[test]
fn lower_if_no_else() {
    let insts = lower("if c { x }", &[], &["c", "x"]);
    // if without else → Mux with 0 as else
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Mux { .. })), 1);
    // Should have a Const(0) for the else branch
    assert!(insts.iter().any(|i| matches!(i, Instruction::Const { value, .. } if value.is_zero())));
}

#[test]
fn lower_for_unrolling() {
    // for i in 0..3 { assert_eq(x, x) }
    // Should unroll to 3 assert_eq instructions
    let insts = lower("for i in 0..3 {\nassert_eq(x, x)\n}", &[], &["x"]);
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::AssertEq { .. })),
        3
    );
    // Should produce 3 Const instructions for i values (0, 1, 2)
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::Const { .. })),
        3
    );
}

#[test]
fn lower_for_uses_iterator() {
    // for i in 0..3 { assert_eq(i, i) }
    // Each iteration binds i to a different constant
    let insts = lower("for i in 0..3 {\nassert_eq(i, i)\n}", &[], &[]);
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::AssertEq { .. })),
        3
    );
}

// ============================================================================
// Blocks
// ============================================================================

#[test]
fn lower_block() {
    // { let y = x; y + 1 }
    let insts = lower("{\nlet y = x\ny + 1\n}", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Add { .. })), 1);
}

// ============================================================================
// Error cases
// ============================================================================

#[test]
fn lower_undeclared_variable() {
    let result = IrLowering::lower_circuit("x + 1", &[], &[]);
    assert!(result.is_err());
}

#[test]
fn lower_unsupported_while() {
    let result = IrLowering::lower_circuit("while true { 1 }", &[], &[]);
    assert!(result.is_err());
}

#[test]
fn lower_wrong_assert_eq_args() {
    let result = IrLowering::lower_circuit("assert_eq(x)", &[], &["x"]);
    assert!(result.is_err());
}

// ============================================================================
// Input ordering
// ============================================================================

#[test]
fn input_order_preserved() {
    let insts = lower("x + y", &["x"], &["y"]);
    // First instruction should be Input(x, Public)
    if let Instruction::Input {
        name, visibility, ..
    } = &insts[0]
    {
        assert_eq!(name, "x");
        assert_eq!(*visibility, Visibility::Public);
    } else {
        panic!("expected Input");
    }
    // Second instruction should be Input(y, Witness)
    if let Instruction::Input {
        name, visibility, ..
    } = &insts[1]
    {
        assert_eq!(name, "y");
        assert_eq!(*visibility, Visibility::Witness);
    } else {
        panic!("expected Input");
    }
}

// ============================================================================
// Convenience API
// ============================================================================

#[test]
fn lower_circuit_convenience() {
    let program = IrLowering::lower_circuit(
        "assert_eq(x * y, z)",
        &["z"],
        &["x", "y"],
    )
    .unwrap();
    assert!(program.instructions.len() >= 4); // 3 inputs + mul + assert_eq
    assert_eq!(
        count(&program.instructions, |i| matches!(
            i,
            Instruction::AssertEq { .. }
        )),
        1
    );
}

// ============================================================================
// Block scoping
// ============================================================================

#[test]
fn block_let_does_not_leak() {
    // `let y` inside the block should not be visible after the block
    let result = IrLowering::lower_circuit(
        "{\nlet y = x\ny\n}\ny",
        &[],
        &["x"],
    );
    assert!(result.is_err(), "y should not be visible outside the block");
}

#[test]
fn nested_block_scoping() {
    // Inner block's `let z` should not leak to outer block
    let result = IrLowering::lower_circuit(
        "{\nlet y = x\n{\nlet z = y\n}\nz\n}",
        &[],
        &["x"],
    );
    assert!(result.is_err(), "z should not be visible outside inner block");
}

#[test]
fn for_body_let_does_not_leak() {
    // `let acc` inside the for body should not leak after the for
    let result = IrLowering::lower_circuit(
        "for i in 0..3 {\nlet acc = x\n}\nacc",
        &[],
        &["x"],
    );
    assert!(result.is_err(), "acc should not be visible after for loop");
}

#[test]
fn if_branch_let_does_not_leak() {
    // `let y` inside the if branch should not be visible after the if
    let result = IrLowering::lower_circuit(
        "if c { let y = x\ny } else { x }\ny",
        &[],
        &["c", "x"],
    );
    assert!(result.is_err(), "y should not be visible after if/else");
}

#[test]
fn outer_binding_survives_block() {
    // `let y` defined before the block should still be accessible after
    let insts = lower(
        "let y = x\n{\nlet z = y\n}\ny",
        &[],
        &["x"],
    );
    // Should succeed — y is defined in the outer scope
    assert!(!insts.is_empty());
}

// ============================================================================
// New operators: !, &&, ||, ==, !=, <, <=, >, >=
// ============================================================================

#[test]
fn lower_not() {
    let insts = lower("!x", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Not { .. })), 1);
}

#[test]
fn lower_double_not() {
    let insts = lower("!!x", &[], &["x"]);
    // Double NOT cancels out — no Not instruction
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Not { .. })), 0);
}

#[test]
fn lower_and() {
    let insts = lower("x && y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::And { .. })), 1);
}

#[test]
fn lower_or() {
    let insts = lower("x || y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Or { .. })), 1);
}

#[test]
fn lower_is_eq() {
    let insts = lower("x == y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsEq { .. })), 1);
}

#[test]
fn lower_is_neq() {
    let insts = lower("x != y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsNeq { .. })), 1);
}

#[test]
fn lower_is_lt() {
    let insts = lower("x < y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLt { .. })), 1);
}

#[test]
fn lower_is_le() {
    let insts = lower("x <= y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLe { .. })), 1);
}

#[test]
fn lower_gt_as_lt_swapped() {
    // x > y should lower to IsLt(y, x) — swapped args
    let insts = lower("x > y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLt { .. })), 1);
    // Should NOT have IsLe
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLe { .. })), 0);
}

#[test]
fn lower_ge_as_le_swapped() {
    // x >= y should lower to IsLe(y, x) — swapped args
    let insts = lower("x >= y", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLe { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsLt { .. })), 0);
}

#[test]
fn lower_assert() {
    let insts = lower("assert(x)", &[], &["x"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Assert { .. })), 1);
}

#[test]
fn lower_bool_true() {
    let insts = lower("true", &[], &[]);
    let last = insts.last().unwrap();
    assert!(matches!(last, Instruction::Const { value, .. } if *value == FieldElement::ONE));
}

#[test]
fn lower_bool_false() {
    let insts = lower("false", &[], &[]);
    let last = insts.last().unwrap();
    assert!(matches!(last, Instruction::Const { value, .. } if value.is_zero()));
}

#[test]
fn lower_assert_eq_via_operators() {
    // assert(x == y) should produce IsEq + Assert
    let insts = lower("assert(x == y)", &[], &["x", "y"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::IsEq { .. })), 1);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Assert { .. })), 1);
}

#[test]
fn lower_chained_and() {
    // a && b && c — should produce 2 And instructions
    let insts = lower("a && b && c", &[], &["a", "b", "c"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::And { .. })), 2);
}

#[test]
fn lower_chained_or() {
    let insts = lower("a || b || c", &[], &["a", "b", "c"]);
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Or { .. })), 2);
}

// ============================================================================
// Error spans
// ============================================================================

#[test]
fn error_has_source_span() {
    let result = IrLowering::lower_circuit("let a = x", &[], &[]);
    let err = result.err().expect("should fail");
    // Should include line:col information
    let msg = format!("{err}");
    assert!(msg.contains("[1:"), "error should include source span, got: {msg}");
}

#[test]
fn error_undeclared_has_span() {
    let result = IrLowering::lower_circuit("x + 1", &[], &[]);
    let err = result.err().expect("should fail");
    let msg = format!("{err}");
    assert!(msg.contains("[1:"), "undeclared error should have span, got: {msg}");
    assert!(msg.contains("x"), "should mention variable name");
}

#[test]
fn lower_wrong_assert_args() {
    let result = IrLowering::lower_circuit("assert(x, y)", &[], &["x", "y"]);
    assert!(result.is_err());
}

// ============================================================================
// H2: Duplicate input name detection
// ============================================================================

#[test]
fn lower_circuit_duplicate_public_rejected() {
    let result = IrLowering::lower_circuit("assert_eq(x, x)", &["x", "x"], &[]);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(msg.contains("duplicate"), "error should mention duplicate: {msg}");
        }
        Ok(_) => panic!("duplicate public name should be rejected"),
    }
}

#[test]
fn lower_circuit_duplicate_public_witness_rejected() {
    let result = IrLowering::lower_circuit("assert_eq(x, x)", &["x"], &["x"]);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(msg.contains("duplicate"), "error should mention duplicate: {msg}");
        }
        Ok(_) => panic!("public+witness overlap should be rejected"),
    }
}

#[test]
fn lower_self_contained_duplicate_rejected() {
    let source = "public x\nwitness x\nassert_eq(x, x)";
    let result = IrLowering::lower_self_contained(source);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(msg.contains("duplicate"), "error should mention duplicate: {msg}");
        }
        Ok(_) => panic!("duplicate in-source declaration should be rejected"),
    }
}
