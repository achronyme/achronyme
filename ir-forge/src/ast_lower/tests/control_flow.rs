use super::*;

// =====================================================================
// Control flow tests
// =====================================================================

#[test]
fn if_expr_produces_mux() {
    let scope = [
        ("c", CompEnvValue::Scalar("c".into())),
        ("a", CompEnvValue::Scalar("a".into())),
        ("b", CompEnvValue::Scalar("b".into())),
    ];
    let expr = compile_expr_with_scope("if c { a } else { b }", &scope).unwrap();
    assert!(
        matches!(expr, CircuitExpr::Mux { .. }),
        "if/else should produce Mux, got {expr:?}"
    );
}

#[test]
fn if_without_else_mux_zero() {
    let scope = [
        ("c", CompEnvValue::Scalar("c".into())),
        ("a", CompEnvValue::Scalar("a".into())),
    ];
    let expr = compile_expr_with_scope("if c { a }", &scope).unwrap();
    if let CircuitExpr::Mux { if_false, .. } = &expr {
        assert_eq!(**if_false, CircuitExpr::Const(FieldConst::zero()));
    } else {
        panic!("expected Mux, got {expr:?}");
    }
}

#[test]
fn if_else_as_statement() {
    // if/else at statement level produces a cond temp, then a Mux expression
    let ir = compile_circuit(
        "public x\npublic out\nlet result = if x { 1 } else { 0 }\nassert_eq(result, out)",
    )
    .unwrap();
    // body[0]: Let { $condN = <cond> } (temporary for condition)
    assert!(
        matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
        "expected $cond temp, got {:?}",
        ir.body[0]
    );
    // body[1]: Let { result = Mux(Var($condN), ...) }
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected Mux value, got {value:?}"
        );
    } else {
        panic!("expected Let, got {:?}", ir.body[1]);
    }
}

#[test]
fn for_range_literal_no_carry_stays_rolled() {
    // Loop without mut accumulator — body has no outer-scope writes,
    // so the rolled `CircuitNode::For` path is preserved (and the
    // instantiate-time unroller handles iteration).
    let ir = compile_circuit(
        "public out\n\
         let arr = [1, 2, 3]\n\
         for i in 0..3 {\n\
             assert_eq(arr[i], arr[i])\n\
         }\n\
         assert_eq(out, out)",
    )
    .unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::Literal { start: 0, end: 3 },
                ..
            }
        )),
        "expected For node with Literal range when no carries; body: {:#?}",
        ir.body
    );
}

#[test]
fn for_range_literal_with_carry_eager_unrolls() {
    // Mut accumulator: predicate detects `acc` as outer-mut + body-write
    // and eager-unrolls at lower. No `CircuitNode::For` survives; the
    // body's SSA chain is materialised inline as N `Let` instances per
    // iteration.
    let ir = compile_circuit(
        "public out\n\
         mut acc = 0\n\
         for i in 0..3 {\n\
             acc = acc + i\n\
         }\n\
         assert_eq(acc, out)",
    )
    .unwrap();
    assert!(
        !ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "carry-set should eager-unroll — no For node should remain. body: {:#?}",
        ir.body
    );
    // Three iter-bound `i` Lets (const 0, 1, 2) plus three `acc$vK`
    // Lets — at minimum 6 Let nodes for the unrolled body.
    let let_count = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::Let { .. }))
        .count();
    assert!(
        let_count >= 6,
        "expected >= 6 Let nodes (3 loop-var binds + 3 acc rebinds), got {let_count}"
    );
}

#[test]
fn for_over_array_with_carry_eager_unrolls() {
    let ir = compile_circuit(
        "public out\n\
         let arr = [1, 2, 3]\n\
         mut acc = 0\n\
         for x in arr {\n\
             acc = acc + x\n\
         }\n\
         assert_eq(acc, out)",
    )
    .unwrap();
    assert!(
        !ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "carry-set over array should eager-unroll — no For node should remain. \
         body: {:#?}",
        ir.body
    );
}

#[test]
fn for_with_dynamic_bound_and_carry_rejected() {
    // Invariant: dynamic bound (`0..n`) combined with a mutable
    // accumulator can't be statically eager-unrolled at lower time,
    // so the predicate forces a clear diagnostic instead of the
    // silent miscompile that the rolled path would produce. Mirrors
    // Noir / Leo / Zokrates rejecting non-constant loop bounds.
    let err = compile_prove_block(
        "public out\n\
         mut acc = 0p0\n\
         for i in 0..n {\n\
             acc = acc + 0p1\n\
         }\n\
         assert_eq(acc, out)",
        &["n", "out"],
    )
    .unwrap_err();
    match err {
        ProveIrError::UnsupportedOperation { description, .. } => {
            assert!(
                description.contains("mutable accumulator")
                    && description.contains("statically-known"),
                "expected dynamic-bound carry diagnostic, got: {description}"
            );
        }
        other => panic!("expected UnsupportedOperation, got {other:?}"),
    }
}

#[test]
fn for_expr_not_array_errors() {
    let err = compile_circuit("public x\nfor i in x {\nassert_eq(i, i)\n}").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn index_constant_resolves() {
    let ir = compile_circuit("public out\nlet arr = [10, 20, 30]\nassert_eq(arr[1], out)").unwrap();
    // arr[1] with constant index should resolve to Var("arr_1")
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[1] {
        assert_eq!(*lhs, CircuitExpr::Var("arr_1".into()));
    } else {
        panic!("expected AssertEq, got {:?}", ir.body[1]);
    }
}

#[test]
fn index_out_of_bounds_errors() {
    let err = compile_circuit("let arr = [1, 2]\nassert_eq(arr[5], arr[0])").unwrap_err();
    assert!(matches!(err, ProveIrError::IndexOutOfBounds { .. }));
}

#[test]
fn block_expr() {
    let scope = [("x", CompEnvValue::Scalar("x".into()))];
    let expr = compile_expr_with_scope("{ x }", &scope).unwrap();
    assert_eq!(expr, CircuitExpr::Var("x".into()));
}

#[test]
fn for_with_accumulator_circuit() {
    // Realistic pattern: accumulate witness array values. The
    // carry-set predicate detects `sum` as an outer mut written in
    // the body and eager-unrolls — no `CircuitNode::For` should
    // survive. Each iter's `sum$vK` Let chains through env to the
    // prior iter's output, so the constraint multiset reflects a
    // real four-step accumulator (not the silent `sum$v1` collision
    // the rolled path would produce).
    let ir = compile_circuit(
        "public total\n\
         witness vals[4]\n\
         mut sum = Field::ZERO\n\
         for i in 0..4 {\n\
             sum = sum + vals[i]\n\
         }\n\
         assert_eq(sum, total)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "vals");
    assert!(
        !ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "post-fix: carry-set body should eager-unroll, no For node should \
         survive. body: {:#?}",
        ir.body
    );
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}
