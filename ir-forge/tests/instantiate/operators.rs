use super::helpers::*;

#[test]
fn instantiate_comparison_eq() {
    let ir = compile_and_instantiate("public a\npublic b\nassert(a == b)");
    let has_is_eq = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsEq { .. }));
    assert!(has_is_eq);
}

#[test]
fn instantiate_comparison_lt() {
    let ir = compile_and_instantiate("public a\npublic b\nassert(a < b)");
    let has_is_lt = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsLt { .. }));
    assert!(has_is_lt);
}

#[test]
fn instantiate_comparison_gt_desugars_to_lt() {
    let ir = compile_and_instantiate("public a\npublic b\nassert(a > b)");
    // a > b → IsLt(b, a) (operands swapped)
    let has_is_lt = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsLt { .. }));
    assert!(has_is_lt, "a > b should desugar to IsLt(b, a)");
}

// --- Boolean ops ---

#[test]
fn instantiate_bool_lowers_and_to_mul() {
    // `a == 1 && b == 1` lowers to two IsEqs and one Mul (And is
    // lowered to Mul at emission time; see
    // ir-forge/src/instantiate/exprs.rs CircuitBoolOp::And). The
    // outer assert lowers to AssertEq(Mul, 1).
    let ir = compile_and_instantiate("public a\npublic b\nassert(a == 1 && b == 1)");
    let has_and = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::And { .. }));
    assert!(!has_and, "And must not appear post-lowering");
    let muls = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .count();
    assert!(muls >= 1, "expected at least one Mul (the And lowering)");
    let iseqs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::IsEq { .. }))
        .count();
    assert_eq!(iseqs, 2, "two `== 1` comparisons");
}

// --- Function inlining ---

#[test]
fn instantiate_user_fn() {
    // Use a runtime input `y` instead of the literal 5, otherwise the
    // peephole const-fold in emit_expr collapses `5 * 2` into Const(10).
    let ir = compile_and_instantiate(
        "public y\npublic out\nfn double(x) { x * 2 }\nassert_eq(double(y), out)",
    );
    let muls = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .count();
    assert_eq!(muls, 1);
}

// --- SSA naming ---

#[test]
fn instantiate_ssa_vars_unique() {
    let ir = compile_and_instantiate(
        "public x\npublic out\nmut a = x\na = a + 1\na = a * 2\nassert_eq(a, out)",
    );
    // All result vars should be unique
    let vars: Vec<SsaVar> = ir.instructions.iter().map(|i| i.result_var()).collect();
    let unique: std::collections::HashSet<SsaVar> = vars.iter().copied().collect();
    assert_eq!(vars.len(), unique.len(), "SSA vars must be unique");
}

// --- Integration: full circuit patterns ---
#[test]
fn audit_poseidon_many_two_args() {
    let ir = compile_and_instantiate(
        "public hash\nwitness a\nwitness b\nassert_eq(poseidon_many(a, b), hash)",
    );
    let hashes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
        .count();
    assert_eq!(hashes, 1, "poseidon_many(a, b) should produce 1 hash");
}

// Pow with exp=1
#[test]
fn audit_pow_one_is_identity() {
    let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 1, out)");
    // x^1 should NOT produce any Mul instructions (identity)
    let muls = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .count();
    assert_eq!(muls, 0, "x^1 should be identity (0 multiplications)");
}

// Unary Neg
#[test]
fn audit_unary_neg() {
    let ir = compile_and_instantiate("public x\npublic out\nassert_eq(-x, out)");
    let negs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Neg { .. }))
        .count();
    assert_eq!(negs, 1);
}

// Unary Not — lowered to Sub(1, x) at emission time.
#[test]
fn audit_unary_not_lowers_to_sub() {
    let ir = compile_and_instantiate("public x\npublic out\nassert_eq(!x, out)");
    let nots = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Not { .. }))
        .count();
    assert_eq!(nots, 0, "Not must not appear post-lowering");
    let subs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Sub { .. }))
        .count();
    assert!(subs >= 1, "expected at least one Sub (the Not lowering)");
}

// Comparison operators Neq, Le, Ge — lowered at emission time so
// IsNeq / IsLe never appear; the lowered shapes are
// 1 - IsEq(...) and 1 - IsLt(swap).
#[test]
fn audit_comparison_neq_lowers_to_iseq_plus_sub() {
    let ir = compile_and_instantiate("public a\npublic b\nassert(a != b)");
    assert!(
        !ir.instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsNeq { .. })),
        "IsNeq must not appear post-lowering"
    );
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsEq { .. })));
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Sub { .. })));
}

#[test]
fn audit_comparison_le_lowers_to_islt_plus_sub() {
    let ir = compile_and_instantiate("public a\npublic b\nassert(a <= b)");
    assert!(
        !ir.instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLe { .. })),
        "IsLe must not appear post-lowering"
    );
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsLt { .. })));
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Sub { .. })));
}

#[test]
fn audit_comparison_ge_lowers_to_islt_plus_sub() {
    // a >= b → 1 - IsLt(a, b)
    let ir = compile_and_instantiate("public a\npublic b\nassert(a >= b)");
    assert!(
        !ir.instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLe { .. })),
        "IsLe must not appear post-lowering"
    );
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsLt { .. })));
    assert!(ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Sub { .. })));
}
