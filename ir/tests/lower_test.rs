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
    let program = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
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
    let result = IrLowering::lower_circuit("{\nlet y = x\ny\n}\ny", &[], &["x"]);
    assert!(result.is_err(), "y should not be visible outside the block");
}

#[test]
fn nested_block_scoping() {
    // Inner block's `let z` should not leak to outer block
    let result = IrLowering::lower_circuit("{\nlet y = x\n{\nlet z = y\n}\nz\n}", &[], &["x"]);
    assert!(
        result.is_err(),
        "z should not be visible outside inner block"
    );
}

#[test]
fn for_body_let_does_not_leak() {
    // `let acc` inside the for body should not leak after the for
    let result = IrLowering::lower_circuit("for i in 0..3 {\nlet acc = x\n}\nacc", &[], &["x"]);
    assert!(result.is_err(), "acc should not be visible after for loop");
}

#[test]
fn if_branch_let_does_not_leak() {
    // `let y` inside the if branch should not be visible after the if
    let result = IrLowering::lower_circuit("if c { let y = x\ny } else { x }\ny", &[], &["c", "x"]);
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
    let result = IrLowering::lower_circuit("let a = x", &[], &[]);
    let err = result.err().expect("should fail");
    // Should include line:col information
    let msg = format!("{err}");
    assert!(
        msg.contains("[1:"),
        "error should include source span, got: {msg}"
    );
}

#[test]
fn error_undeclared_has_span() {
    let result = IrLowering::lower_circuit("x + 1", &[], &[]);
    let err = result.err().expect("should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("[1:"),
        "undeclared error should have span, got: {msg}"
    );
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
    let result = IrLowering::lower_circuit("assert_eq(x, x)", &["x"], &["x"]);
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
    let result = IrLowering::lower_self_contained(source);
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

#[test]
fn dce_preserves_range_check_unused_result() {
    // range_check(x, 8) — result not used in assert_eq, but must not be eliminated
    let source = "range_check(x, 8)";
    let mut program = IrLowering::lower_circuit(source, &[], &["x"]).unwrap();
    let before = program.instructions.len();
    let has_rc_before = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::RangeCheck { .. }));
    assert!(has_rc_before, "should have RangeCheck before optimization");

    ir::passes::optimize(&mut program);

    let has_rc_after = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::RangeCheck { .. }));
    assert!(
        has_rc_after,
        "RangeCheck must survive DCE even when result is unused"
    );
    // Const instructions for the bits literal may be folded, but RangeCheck itself must remain
    assert!(
        program.instructions.len() <= before,
        "optimization should not add instructions"
    );
}

#[test]
fn dce_eliminates_poseidon_unused_result() {
    // poseidon(a, b) — result not used → DCE should eliminate it
    let source = "poseidon(a, b)";
    let mut program = IrLowering::lower_circuit(source, &[], &["a", "b"]).unwrap();
    let has_poseidon_before = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::PoseidonHash { .. }));
    assert!(
        has_poseidon_before,
        "should have PoseidonHash before optimization"
    );

    ir::passes::optimize(&mut program);

    let has_poseidon_after = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::PoseidonHash { .. }));
    assert!(
        !has_poseidon_after,
        "unused PoseidonHash should be eliminated by DCE"
    );
}

#[test]
fn dce_preserves_assert_eq_and_deps() {
    // assert_eq(x * y, out) — the Mul is used by AssertEq, neither should be eliminated
    let source = "assert_eq(x * y, out)";
    let mut program = IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);

    let has_mul = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Mul { .. }));
    let has_assert = program
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::AssertEq { .. }));
    assert!(has_mul, "Mul feeding AssertEq must survive DCE");
    assert!(has_assert, "AssertEq must survive DCE");
}

#[test]
fn dce_eliminates_unused_add() {
    // let unused = x + 1; assert_eq(x, out) — the Add should be eliminated
    let source = "let unused = x + 1\nassert_eq(x, out)";
    let mut program = IrLowering::lower_circuit(source, &["out"], &["x"]).unwrap();
    let adds_before = program
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();

    ir::passes::optimize(&mut program);

    let adds_after = program
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();
    assert!(
        adds_after < adds_before,
        "unused Add should be eliminated by DCE (before={adds_before}, after={adds_after})"
    );
}

// ============================================================================
// Type annotation tests
// ============================================================================

#[test]
fn typed_public_sets_ir_type() {
    let (_, _, prog) =
        IrLowering::lower_self_contained("public x: Field\nassert_eq(x, x)").expect("should lower");
    // The Input instruction for x should have type Field
    for inst in &prog.instructions {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "x" {
                assert_eq!(
                    prog.get_type(*result),
                    Some(ir::IrType::Field),
                    "public x: Field should have IrType::Field"
                );
            }
        }
    }
}

#[test]
fn typed_witness_bool_sets_ir_type() {
    let (_, _, prog) =
        IrLowering::lower_self_contained("public x: Field\nwitness b: Bool\nassert_eq(x, b)")
            .expect("should lower");
    for inst in &prog.instructions {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "b" {
                assert_eq!(
                    prog.get_type(*result),
                    Some(ir::IrType::Bool),
                    "witness b: Bool should have IrType::Bool"
                );
            }
        }
    }
}

#[test]
fn typed_let_field_compiles() {
    // let h: Field = poseidon(a, b) — should compile without error
    let (_, _, prog) = IrLowering::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet h: Field = poseidon(a, b)\nassert_eq(h, h)",
    )
    .expect("typed let should compile");
    assert!(!prog.instructions.is_empty());
}

#[test]
fn typed_let_bool_compiles() {
    // let ok: Bool = x == y — should compile without error
    let (_, _, prog) = IrLowering::lower_self_contained(
        "public x: Field\nwitness y: Field\nlet ok: Bool = x == y\nassert(ok)",
    )
    .expect("typed let Bool should compile");
    assert!(!prog.instructions.is_empty());
}

#[test]
fn typed_let_bool_from_field_arithmetic_fails() {
    // let bad: Bool = x + y — x + y produces Field, cannot be annotated as Bool
    let result = IrLowering::lower_self_contained(
        "public x: Field\nwitness y: Field\nlet bad: Bool = x + y",
    );
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("annotation mismatch") || msg.contains("Bool"),
                "should mention type mismatch: {msg}"
            );
        }
        Ok(_) => panic!("Field expression annotated as Bool should fail"),
    }
}

#[test]
fn typed_fn_with_return_type() {
    let source = r#"
witness a: Field
witness b: Field
fn hash(x: Field, y: Field) -> Field {
    poseidon(x, y)
}
let h: Field = hash(a, b)
assert_eq(h, h)
"#;
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("typed fn should compile");
    assert!(!prog.instructions.is_empty());
}

#[test]
fn typed_fn_param_mismatch_fails() {
    // Pass a Field value where Bool is expected
    let source = r#"
witness x: Field
fn check(b: Bool) { assert(b) }
check(x)
"#;
    let result = IrLowering::lower_self_contained(source);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("annotation mismatch") || msg.contains("Bool"),
                "should mention type mismatch: {msg}"
            );
        }
        Ok(_) => panic!("passing Field to Bool param should fail"),
    }
}

#[test]
fn bool_subtype_of_field_allowed() {
    // Bool values can be used where Field is expected
    let source = r#"
witness a: Field
witness b: Field
let ok: Bool = a == b
let x: Field = ok
assert_eq(x, x)
"#;
    let (_, _, prog) =
        IrLowering::lower_self_contained(source).expect("Bool used as Field should compile");
    assert!(!prog.instructions.is_empty());
}

#[test]
fn untyped_code_unchanged() {
    // All existing untyped code should still work identically
    let source = "public x\nwitness y\nassert_eq(x + y, x * y)";
    let (pub_names, wit_names, prog) =
        IrLowering::lower_self_contained(source).expect("untyped should compile");
    assert_eq!(pub_names, vec!["x"]);
    assert_eq!(wit_names, vec!["y"]);
    assert!(!prog.instructions.is_empty());
}

#[test]
fn comparison_result_is_bool() {
    let (_, _, prog) = IrLowering::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet eq: Bool = a == b\nassert(eq)",
    )
    .expect("should lower");
    // Find IsEq instruction, check its result has Bool type
    for inst in &prog.instructions {
        if let Instruction::IsEq { result, .. } = inst {
            assert_eq!(prog.get_type(*result), Some(ir::IrType::Bool));
        }
    }
}

#[test]
fn not_rejects_field_operand() {
    // !x where x: Field should fail
    let result =
        IrLowering::lower_self_contained("witness x: Field\nlet bad: Bool = !x\nassert(bad)");
    assert!(result.is_err(), "!Field should fail");
}

#[test]
fn not_accepts_bool_operand() {
    let result = IrLowering::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet ok = !(a == b)\nassert(ok)",
    );
    assert!(result.is_ok(), "!Bool should compile");
}

#[test]
fn mixed_typed_and_untyped_inputs() {
    // Some inputs typed, some not — gradual typing
    let source = "public x: Field\nwitness y\nassert_eq(x, y)";
    let (_, _, prog) =
        IrLowering::lower_self_contained(source).expect("mixed typing should compile");
    // x should have type, y should not
    let mut x_typed = false;
    let mut y_untyped = true;
    for inst in &prog.instructions {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "x" {
                x_typed = prog.get_type(*result).is_some();
            }
            if name == "y" {
                y_untyped = prog.get_type(*result).is_none();
            }
        }
    }
    assert!(x_typed, "x: Field should have type");
    assert!(y_untyped, "y (no annotation) should have no type");
}

#[test]
fn if_branches_propagate_type() {
    let source = r#"
witness a: Field
witness b: Field
witness c: Field
let r = if true { a == b } else { a == c }
assert(r)
"#;
    let (_, _, prog) =
        IrLowering::lower_self_contained(source).expect("if with matching branch types");
    // The Mux result should have Bool type since both branches are Bool
    for inst in &prog.instructions {
        if let Instruction::Mux { result, .. } = inst {
            assert_eq!(prog.get_type(*result), Some(ir::IrType::Bool));
        }
    }
}

// ============================================================================
// Type annotation enforcement (soundness fixes)
// ============================================================================

#[test]
fn let_bool_on_untyped_emits_range_check() {
    // `let b: Bool = x` where x is an untyped witness — must emit RangeCheck
    let source = "witness x\nlet b: Bool = x\nassert(b)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "let b: Bool on untyped witness must emit RangeCheck(1), found {rc_count}"
    );
}

#[test]
fn let_bool_on_typed_bool_no_extra_range_check() {
    // `let b: Bool = (a == c)` — a == c already produces Bool, no extra RangeCheck needed
    let source = "witness a\nwitness c\nlet b: Bool = a == c\nassert(b)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert_eq!(
        rc_count, 0,
        "let b: Bool on already-Bool value should NOT emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn let_field_on_untyped_no_enforcement() {
    // `let f: Field = x` — Field annotation on untyped is safe, no RangeCheck
    let source = "witness x\nlet f: Field = x\nassert_eq(f, f)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { .. })
    });
    assert_eq!(
        rc_count, 0,
        "let f: Field should not emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn array_annotation_validates_length() {
    // `let a: Field[2] = [x, y, z]` — length mismatch should error
    let source = "witness x\nwitness y\nwitness z\nlet a: Field[2] = [x, y, z]";
    let result = IrLowering::lower_self_contained(source);
    assert!(result.is_err(), "array length mismatch should fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("length mismatch"),
        "should mention length mismatch: {msg}"
    );
}

#[test]
fn array_bool_on_untyped_elements_enforces() {
    // `let a: Bool[2] = [x, y]` where x, y are untyped — RangeCheck per element
    let source = "witness x\nwitness y\nlet a: Bool[2] = [x, y]\nassert(a[0])";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 2,
        "Bool[2] on untyped elements should emit at least 2 RangeChecks, found {rc_count}"
    );
}

#[test]
fn fn_return_bool_on_untyped_body_enforces() {
    // fn f(x) -> Bool { x } — x is untyped, return type is Bool → enforce
    let source = r#"
witness w
fn f(x: Field) -> Bool { x }
let r = f(w)
assert(r)
"#;
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "fn -> Bool with untyped body should emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn fn_param_bool_on_untyped_arg_enforces() {
    // fn f(b: Bool) { assert(b) } called with untyped witness → enforce
    let source = r#"
witness w
fn f(b: Bool) { assert(b) }
f(w)
"#;
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "fn(b: Bool) with untyped arg should emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn neg_result_has_field_type() {
    // `-x` should have type Field
    let source = "witness x\nlet n = -x\nassert_eq(n, n)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    for inst in &prog.instructions {
        if let Instruction::Neg { result, .. } = inst {
            assert_eq!(
                prog.get_type(*result),
                Some(ir::IrType::Field),
                "Neg result should have Field type"
            );
        }
    }
}

// ============================================================================
// T-01: witness x: Bool must emit RangeCheck
// ============================================================================

#[test]
fn witness_bool_decl_emits_range_check() {
    let source = "witness flag: Bool\nassert(flag)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "witness flag: Bool should emit RangeCheck(flag, 1), found {rc_count}"
    );
}

#[test]
fn witness_bool_array_decl_emits_range_checks() {
    let source = "witness flags[3]: Bool\nassert(flags[0])";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 3,
        "witness flags[3]: Bool should emit 3 RangeChecks, found {rc_count}"
    );
}

#[test]
fn public_bool_decl_emits_range_check() {
    let source = "public flag: Bool\nassert(flag)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    let rc_count = count(&prog.instructions, |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "public flag: Bool should emit RangeCheck(flag, 1), found {rc_count}"
    );
}

// ============================================================================
// T-03: array Bool[N] annotation must check type compatibility
// ============================================================================

#[test]
fn array_bool_annotation_rejects_field_typed_element() {
    // `a + b` produces Field type, which is incompatible with Bool[1] annotation.
    let source = r#"
witness a: Field
witness b: Field
let arr: Bool[1] = [a + b]
"#;
    let result = IrLowering::lower_self_contained(source);
    assert!(
        result.is_err(),
        "Bool[1] annotation on Field-typed element should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("AnnotationMismatch") || err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

// ============================================================================
// T-04: Annotation shape must match value shape
// ============================================================================

#[test]
fn scalar_annotation_on_array_rejected() {
    // `let arr: Bool = [x, y]` — scalar annotation on array value
    let source = "witness x\nwitness y\nlet arr: Bool = [x, y]";
    let result = IrLowering::lower_self_contained(source);
    assert!(
        result.is_err(),
        "scalar Bool annotation on array literal should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

#[test]
fn scalar_field_annotation_on_array_rejected() {
    let source = "witness x\nlet arr: Field = [x]";
    let result = IrLowering::lower_self_contained(source);
    assert!(
        result.is_err(),
        "scalar Field annotation on array literal should fail"
    );
}

#[test]
fn array_annotation_on_scalar_rejected() {
    // `let x: Field[3] = expr` — array annotation on scalar value
    let source = "witness x\nlet y: Field[3] = x";
    let result = IrLowering::lower_self_contained(source);
    assert!(
        result.is_err(),
        "array Field[3] annotation on scalar value should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

#[test]
fn array_bool_annotation_on_scalar_rejected() {
    let source = "witness x\nlet y: Bool[2] = x";
    let result = IrLowering::lower_self_contained(source);
    assert!(
        result.is_err(),
        "array Bool[2] annotation on scalar value should fail"
    );
}

// ============================================================================
// T-05: pow_by_squaring results must be typed Field
// ============================================================================

#[test]
fn pow_result_has_field_type() {
    let source = "witness x\nlet p = x ^ 3\nassert_eq(p, p)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    // The last Mul in the pow chain should have Field type
    let mul_results: Vec<_> = prog
        .instructions
        .iter()
        .filter_map(|i| {
            if let Instruction::Mul { result, .. } = i {
                Some(*result)
            } else {
                None
            }
        })
        .collect();
    assert!(!mul_results.is_empty(), "x^3 should emit at least one Mul");
    for r in &mul_results {
        assert_eq!(
            prog.get_type(*r),
            Some(ir::IrType::Field),
            "pow Mul result should have Field type"
        );
    }
}

#[test]
fn pow_zero_result_has_field_type() {
    let source = "witness x\nlet p = x ^ 0\nassert_eq(p, p)";
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    // x^0 = Const(1), should be typed Field
    let const_ones: Vec<_> = prog
        .instructions
        .iter()
        .filter_map(|i| {
            if let Instruction::Const { result, value } = i {
                if *value == memory::FieldElement::ONE {
                    Some(*result)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    // At least one Const(1) should exist and be typed Field
    let any_field = const_ones
        .iter()
        .any(|r| prog.get_type(*r) == Some(ir::IrType::Field));
    assert!(any_field, "x^0 Const(1) should have Field type");
}

// ============================================================================
// T-06: Field[N] annotation preserves Bool type on elements
// ============================================================================

#[test]
fn field_array_preserves_bool_element_type() {
    // (a == b) is Bool-typed; putting it in Field[1] should NOT widen to Field
    let source = r#"
witness a: Field
witness b: Field
let eq = a == b
let arr: Field[1] = [eq]
"#;
    let (_, _, prog) = IrLowering::lower_self_contained(source).expect("should lower");
    // Find the IsEq result variable
    for inst in &prog.instructions {
        if let Instruction::IsEq { result, .. } = inst {
            assert_eq!(
                prog.get_type(*result),
                Some(ir::IrType::Bool),
                "IsEq result in Field[1] array should preserve Bool type"
            );
        }
    }
}
