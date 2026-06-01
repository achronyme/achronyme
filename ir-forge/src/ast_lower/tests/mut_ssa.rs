use super::*;

// =====================================================================
// Mut-to-SSA desugaring tests
// =====================================================================

#[test]
fn mut_decl_basic() {
    let ir = compile_circuit("public x\nmut acc = x\nassert_eq(acc, x)").unwrap();
    // mut acc = x → Let { name: "acc", value: Var("x") }
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "acc"
    ));
}

#[test]
fn mut_reassignment_creates_ssa_version() {
    let ir = compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
    // body[0]: Let { name: "acc", value: Var("x") }
    // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
    // body[2]: AssertEq { Var("acc$v1"), Var("x") }
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "acc"
    ));
    assert!(matches!(
        &ir.body[1],
        CircuitNode::Let { name, .. } if name == "acc$v1"
    ));
    // AssertEq should reference the latest SSA name
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[2] {
        assert_eq!(*lhs, CircuitExpr::Var("acc$v1".into()));
    } else {
        panic!("expected AssertEq, got {:?}", ir.body[2]);
    }
}

#[test]
fn mut_multiple_reassignments() {
    let ir =
        compile_circuit("public x\nmut a = 0\na = a + 1\na = a + 2\na = a + 3\nassert_eq(a, x)")
            .unwrap();
    // Let("a"), Let("a$v1"), Let("a$v2"), Let("a$v3"), AssertEq(Var("a$v3"), ...)
    assert!(matches!(
        &ir.body[0],
        CircuitNode::Let { name, .. } if name == "a"
    ));
    assert!(matches!(
        &ir.body[1],
        CircuitNode::Let { name, .. } if name == "a$v1"
    ));
    assert!(matches!(
        &ir.body[2],
        CircuitNode::Let { name, .. } if name == "a$v2"
    ));
    assert!(matches!(
        &ir.body[3],
        CircuitNode::Let { name, .. } if name == "a$v3"
    ));
    // The final assert_eq should use a$v3
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
        assert_eq!(*lhs, CircuitExpr::Var("a$v3".into()));
    } else {
        panic!("expected AssertEq");
    }
}

#[test]
fn mut_reassignment_uses_previous_version() {
    // acc = acc + 1 should reference the PREVIOUS version of acc in the RHS
    let ir = compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
    // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        // The RHS should reference "acc" (v0), not "acc$v1"
        assert_eq!(
            *value,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("acc".into())),
                rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
            }
        );
    } else {
        panic!("expected Let node");
    }
}

#[test]
fn assign_to_immutable_errors() {
    let err = compile_circuit("public x\nlet a = x\na = 42\nassert_eq(a, x)").unwrap_err();
    assert!(
        matches!(err, ProveIrError::UnsupportedOperation { ref description, .. }
            if description.contains("not declared with `mut`")),
        "expected mut error, got {err}"
    );
}

#[test]
fn assign_to_undeclared_errors() {
    let err = compile_circuit("public x\nfoo = 42\nassert_eq(foo, x)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn mut_in_accumulator_pattern() {
    // Common pattern: accumulate in a loop (simulated without for, just sequential)
    let ir = compile_circuit(
        "public total\n\
         witness a\n\
         witness b\n\
         witness c\n\
         mut acc = Field::ZERO\n\
         acc = acc + a\n\
         acc = acc + b\n\
         acc = acc + c\n\
         assert_eq(acc, total)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
    // acc, acc$v1, acc$v2, acc$v3, assert_eq
    assert_eq!(ir.body.len(), 5);
    // Last AssertEq should use acc$v3
    if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
        assert_eq!(*lhs, CircuitExpr::Var("acc$v3".into()));
    } else {
        panic!("expected AssertEq");
    }
}
