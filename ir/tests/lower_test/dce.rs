use super::*;

#[test]
fn dce_preserves_range_check_unused_result() {
    // range_check(x, 8) — result not used in assert_eq, but must not be eliminated
    let source = "range_check(x, 8)";
    let mut program = IrLowering::<memory::Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();
    let before = program.len();
    let has_rc_before = program
        .iter()
        .any(|i| matches!(i, Instruction::RangeCheck { .. }));
    assert!(has_rc_before, "should have RangeCheck before optimization");

    ir::passes::optimize(&mut program);

    let has_rc_after = program
        .iter()
        .any(|i| matches!(i, Instruction::RangeCheck { .. }));
    assert!(
        has_rc_after,
        "RangeCheck must survive DCE even when result is unused"
    );
    // Const instructions for the bits literal may be folded, but RangeCheck itself must remain
    assert!(
        program.len() <= before,
        "optimization should not add instructions"
    );
}

#[test]
fn dce_eliminates_poseidon_unused_result() {
    // poseidon(a, b) — result not used → DCE should eliminate it
    let source = "poseidon(a, b)";
    let mut program =
        IrLowering::<memory::Bn254Fr>::lower_circuit(source, &[], &["a", "b"]).unwrap();
    let has_poseidon_before = program
        .iter()
        .any(|i| matches!(i, Instruction::PoseidonHash { .. }));
    assert!(
        has_poseidon_before,
        "should have PoseidonHash before optimization"
    );

    ir::passes::optimize(&mut program);

    let has_poseidon_after = program
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
    let mut program =
        IrLowering::<memory::Bn254Fr>::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);

    let has_mul = program.iter().any(|i| matches!(i, Instruction::Mul { .. }));
    let has_assert = program
        .iter()
        .any(|i| matches!(i, Instruction::AssertEq { .. }));
    assert!(has_mul, "Mul feeding AssertEq must survive DCE");
    assert!(has_assert, "AssertEq must survive DCE");
}

#[test]
fn dce_eliminates_unused_add() {
    // let unused = x + 1; assert_eq(x, out) — the Add should be eliminated
    let source = "let unused = x + 1\nassert_eq(x, out)";
    let mut program =
        IrLowering::<memory::Bn254Fr>::lower_circuit(source, &["out"], &["x"]).unwrap();
    let adds_before = program
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();

    ir::passes::optimize(&mut program);

    let adds_after = program
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
