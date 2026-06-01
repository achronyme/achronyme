use super::*;

// =====================================================================
// Audit finding regression tests
// =====================================================================

// G1: Duplicate input declarations
#[test]
fn audit_duplicate_public_public() {
    let err = compile_circuit("public x\npublic x").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
        "expected DuplicateInput, got {err:?}"
    );
}

#[test]
fn audit_duplicate_public_witness() {
    let err = compile_circuit("public x\nwitness x").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
        "expected DuplicateInput, got {err:?}"
    );
}

#[test]
fn audit_duplicate_witness_witness() {
    let err = compile_circuit("witness a\nwitness a").unwrap_err();
    assert!(
        matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "a"),
        "expected DuplicateInput, got {err:?}"
    );
}

// G2: assert_eq/assert as sub-expressions must emit constraint
#[test]
fn audit_assert_eq_in_let_emits_constraint() {
    let ir = compile_circuit("public a\npublic b\nlet x = assert_eq(a, b)").unwrap();
    let has_assert_eq = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. }));
    assert!(
        has_assert_eq,
        "assert_eq at expression level must emit AssertEq node, body: {:#?}",
        ir.body
    );
}

#[test]
fn audit_assert_in_let_emits_constraint() {
    let ir = compile_circuit("public a\nlet x = assert(a)").unwrap();
    let has_assert = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Assert { .. }));
    assert!(
        has_assert,
        "assert at expression level must emit Assert node, body: {:#?}",
        ir.body
    );
}

// G4: Double function inlining produces unique names
#[test]
fn audit_double_fn_inlining_unique_names() {
    let source = "\
        public out\n\
        fn double(a) { a * 2 }\n\
        let x = double(1)\n\
        let y = double(2)\n\
        assert_eq(x + y, out)";
    let ir = compile_circuit(source).unwrap();
    // Collect all Let names
    let names: Vec<&str> = ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::Let { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    // All names should be unique
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len(), "duplicate Let names: {names:?}");
}

// G5: range_check with very large bit count
#[test]
fn audit_range_check_large_bits_rejected() {
    let source = "public x\nrange_check(x, 5000000000)";
    let err = compile_circuit(source).unwrap_err();
    assert!(
        matches!(err, ProveIrError::UnsupportedOperation { .. }),
        "expected error for large bit count, got {err:?}"
    );
}

// G6: for range start > end (zero iterations, should not error)
#[test]
fn audit_for_range_start_gt_end() {
    // start > end means 0 iterations (saturating_sub), should compile fine
    let source = "public out\nfor i in 5..3 { }\nassert_eq(0, out)";
    let ir = compile_circuit(source).unwrap();
    assert!(
        ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "expected For node"
    );
}

// G7: poseidon_many with 1 argument
#[test]
fn audit_poseidon_many_one_arg() {
    let source = "public a\nposeidon_many(a)";
    let err = compile_circuit(source).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("at least 2"),
        "expected 'at least 2' in error, got: {msg}"
    );
}

// G8: else-if chain
#[test]
fn audit_else_if_chain() {
    let source = "\
        public x\n\
        public out\n\
        let r = if x { 1 } else if x { 2 } else { 3 }\n\
        assert_eq(r, out)";
    let ir = compile_circuit(source).unwrap();
    // Should compile without error and produce Mux nodes
    let has_mux = ir.body.iter().any(|n| match n {
        CircuitNode::Let { value, .. } => matches!(value, CircuitExpr::Mux { .. }),
        _ => false,
    });
    assert!(has_mux, "expected Mux from else-if chain");
}

// For loop range too large
#[test]
fn audit_for_range_too_large() {
    let source = "public out\nfor i in 0..2000000 { }\nassert_eq(0, out)";
    let err = compile_circuit(source).unwrap_err();
    assert!(
        matches!(err, ProveIrError::RangeTooLarge { .. }),
        "expected RangeTooLarge, got {err:?}"
    );
}

// =====================================================================
