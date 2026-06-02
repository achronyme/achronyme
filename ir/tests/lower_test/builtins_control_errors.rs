use super::*;

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
    assert!(insts
        .iter()
        .any(|i| matches!(i, Instruction::Const { value, .. } if value.is_zero())));
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
    assert_eq!(count(&insts, |i| matches!(i, Instruction::Const { .. })), 3);
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
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("x + 1", &[], &[]);
    assert!(result.is_err());
}

#[test]
fn lower_unsupported_while() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("while true { 1 }", &[], &[]);
    assert!(result.is_err());
}

#[test]
fn lower_wrong_assert_eq_args() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("assert_eq(x)", &[], &["x"]);
    assert!(result.is_err());
}

#[test]
fn lower_assert_eq_with_message() {
    let insts = lower("assert_eq(x, y, \"values must match\")", &["x"], &["y"]);
    let has_msg = insts.iter().any(
        |i| matches!(i, Instruction::AssertEq { message: Some(m), .. } if m == "values must match"),
    );
    assert!(has_msg, "assert_eq should carry the custom message");
}

#[test]
fn lower_assert_eq_non_string_message_rejected() {
    let result =
        IrLowering::<memory::Bn254Fr>::lower_circuit("assert_eq(x, y, 42)", &["x"], &["y"]);
    assert!(result.is_err(), "non-string 3rd arg should be rejected");
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
    let program =
        IrLowering::<memory::Bn254Fr>::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"])
            .unwrap();
    assert!(program.len() >= 4); // 3 inputs + mul + assert_eq
    assert_eq!(
        count(program.instructions(), |i| matches!(
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
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("{\nlet y = x\ny\n}\ny", &[], &["x"]);
    assert!(result.is_err(), "y should not be visible outside the block");
}

#[test]
fn nested_block_scoping() {
    // Inner block's `let z` should not leak to outer block
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "{\nlet y = x\n{\nlet z = y\n}\nz\n}",
        &[],
        &["x"],
    );
    assert!(
        result.is_err(),
        "z should not be visible outside inner block"
    );
}

#[test]
fn for_body_let_does_not_leak() {
    // `let acc` inside the for body should not leak after the for
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "for i in 0..3 {\nlet acc = x\n}\nacc",
        &[],
        &["x"],
    );
    assert!(result.is_err(), "acc should not be visible after for loop");
}

#[test]
fn if_branch_let_does_not_leak() {
    // `let y` inside the if branch should not be visible after the if
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "if c { let y = x\ny } else { x }\ny",
        &[],
        &["c", "x"],
    );
    assert!(result.is_err(), "y should not be visible after if/else");
}

#[test]
fn outer_binding_survives_block() {
    // `let y` defined before the block should still be accessible after
    let insts = lower("let y = x\n{\nlet z = y\n}\ny", &[], &["x"]);
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
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::Assert { .. })),
        1
    );
}

#[test]
fn lower_assert_with_message() {
    let insts = lower("assert(x, \"must be true\")", &[], &["x"]);
    let has_msg = insts
        .iter()
        .any(|i| matches!(i, Instruction::Assert { message: Some(m), .. } if m == "must be true"));
    assert!(has_msg, "assert should carry the custom message");
}

#[test]
fn lower_assert_non_string_message_rejected() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("assert(x, 42)", &[], &["x"]);
    assert!(result.is_err(), "non-string 2nd arg should be rejected");
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
    assert_eq!(
        count(&insts, |i| matches!(i, Instruction::Assert { .. })),
        1
    );
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
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("let a = x", &[], &[]);
    let err = result.expect_err("should fail");
    // Should include line:col information
    let msg = format!("{err}");
    assert!(
        msg.contains("[1:"),
        "error should include source span, got: {msg}"
    );
}

#[test]
fn error_undeclared_has_span() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("x + 1", &[], &[]);
    let err = result.expect_err("should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("[1:"),
        "undeclared error should have span, got: {msg}"
    );
    assert!(msg.contains("x"), "should mention variable name");
}

#[test]
fn lower_wrong_assert_args() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("assert(x, y)", &[], &["x", "y"]);
    assert!(result.is_err());
}

// ============================================================================
// H2: Duplicate input name detection
// ============================================================================

#[test]
fn lower_circuit_duplicate_public_rejected() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("assert_eq(x, x)", &["x", "x"], &[]);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("duplicate"),
                "error should mention duplicate: {msg}"
            );
        }
        Ok(_) => panic!("duplicate public name should be rejected"),
    }
}

#[test]
fn lower_circuit_duplicate_public_witness_rejected() {
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit("assert_eq(x, x)", &["x"], &["x"]);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("duplicate"),
                "error should mention duplicate: {msg}"
            );
        }
        Ok(_) => panic!("public+witness overlap should be rejected"),
    }
}

#[test]
fn lower_self_contained_duplicate_rejected() {
    let source = "public x\nwitness x\nassert_eq(x, x)";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("duplicate"),
                "error should mention duplicate: {msg}"
            );
        }
        Ok(_) => panic!("duplicate in-source declaration should be rejected"),
    }
}

// ============================================================================
// T4: DCE safety — RangeCheck / PoseidonHash must survive optimization
// ============================================================================
