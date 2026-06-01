use super::*;

// OuterScope function tests
// =====================================================================

#[test]
fn outer_scope_fn_in_prove_block() {
    // Parse a FnDecl to pass via OuterScope
    let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
    let fn_stmt = prog.stmts[0].clone();

    let outer = OuterScope {
        values: [("val", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![fn_stmt],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public expected\nassert_eq(double(val), expected)",
        &outer,
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "val");
}

#[test]
fn outer_scope_fn_in_circuit() {
    // Functions before circuit declaration should be available via OuterScope
    let source = "\
        fn double(x) { x * 2 }\n\
        circuit test(a: Public, out: Public) {\n\
            assert_eq(double(a), out)\n\
        }";
    let ir = ProveIrCompiler::<Bn254Fr>::compile_circuit(source, None).unwrap();
    assert_eq!(ir.public_inputs.len(), 2);
    // double(a) should have been inlined — no function calls remain
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn outer_scope_fn_overridden_by_local() {
    // A local fn with the same name should override the outer scope fn
    let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
    let fn_stmt = prog.stmts[0].clone();

    let outer = OuterScope {
        values: [("val", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        functions: vec![fn_stmt],
        ..Default::default()
    };
    // Local fn triple overrides nothing, but local double overrides outer double
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "fn double(x) { x * 3 }\npublic expected\nassert_eq(double(val), expected)",
        &outer,
    )
    .unwrap();
    // Should compile without error — the local double (x*3) is used
    assert_eq!(ir.public_inputs.len(), 1);
}

// ── Dynamic loop bounds ─────────────────────────────────────

#[test]
fn dynamic_loop_bound_capture() {
    // `for i in 0..n` where n is a capture from outer scope. Body has
    // no mut accumulator, so the rolled `WithCapture` path is preserved
    // (instantiation resolves n from captures). The carry-set
    // detection only diverts to eager-unroll when a carry-set is
    // present.
    let outer = OuterScope {
        values: [
            ("n", OuterScopeEntry::Scalar),
            ("a", OuterScopeEntry::Scalar),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        functions: vec![],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public result\nfor i in 0..n { assert_eq(a, a) }\nassert_eq(result, result)",
        &outer,
    )
    .unwrap();
    assert!(!ir.captures.is_empty(), "n should be a capture");
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::WithCapture { start: 0, .. },
                ..
            }
        )),
        "expected For with WithCapture range"
    );
}

#[test]
fn dynamic_loop_bound_expr() {
    // `for i in 0..n+1` where n is a capture. Body has no mut
    // accumulator — same rationale as `dynamic_loop_bound_capture`.
    let outer = OuterScope {
        values: [
            ("n", OuterScopeEntry::Scalar),
            ("a", OuterScopeEntry::Scalar),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        functions: vec![],
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public result\nfor i in 0..n+1 { assert_eq(a, a) }\nassert_eq(result, result)",
        &outer,
    )
    .unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(
            n,
            CircuitNode::For {
                range: ForRange::WithExpr { start: 0, .. },
                ..
            }
        )),
        "expected For with WithExpr range"
    );
}
