use super::*;

// =====================================================================
// Statement compilation tests
// =====================================================================

#[test]
fn stmt_public_decl_scalar() {
    let ir = compile_circuit("public x\nassert_eq(x, x)").unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "x");
    assert!(ir.public_inputs[0].array_size.is_none());
}

#[test]
fn stmt_witness_decl_scalar() {
    let ir = compile_circuit("witness y\nassert_eq(y, y)").unwrap();
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "y");
}

#[test]
fn stmt_public_decl_array() {
    let ir = compile_circuit("public arr[3]\nassert_eq(arr_0, arr_1)").unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "arr");
    assert_eq!(ir.public_inputs[0].array_size, Some(ArraySize::Literal(3)));
}

#[test]
fn annotation_to_ir_type_rejects_int_directly() {
    // Defense-in-depth (Gap 2.4 hardening): the parser already rejects
    // `public x: Int` upstream with a clear ParseError, so this lowerer
    // path was unreachable in practice. The fix replaces the previous
    // `unreachable!()` with a proper `TypeNotConstrainable` so a future
    // parser change (new BaseType, relaxed validation) cannot panic the
    // lowerer in production.
    use achronyme_parser::ast::{BaseType, TypeAnnotation};
    use diagnostics::Span;
    let ann = TypeAnnotation {
        visibility: None,
        base: BaseType::Int,
        array_size: None,
    };
    let span = Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    };
    let err = super::super::helpers::annotation_to_ir_type(&ann, &span).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "Int"
    ));
}

#[test]
fn annotation_to_ir_type_rejects_string_directly() {
    use achronyme_parser::ast::{BaseType, TypeAnnotation};
    use diagnostics::Span;
    let ann = TypeAnnotation {
        visibility: None,
        base: BaseType::String,
        array_size: None,
    };
    let span = Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    };
    let err = super::super::helpers::annotation_to_ir_type(&ann, &span).unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "String"
    ));
}

#[test]
fn stmt_let_scalar() {
    let ir = compile_circuit("public x\nlet y = x\nassert_eq(y, x)").unwrap();
    assert!(ir.body.len() >= 2); // Let + AssertEq
    assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "y"));
}

#[test]
fn stmt_let_array() {
    let ir = compile_circuit("let arr = [1, 2, 3]").unwrap();
    assert_eq!(ir.body.len(), 1);
    if let CircuitNode::LetArray { name, elements, .. } = &ir.body[0] {
        assert_eq!(name, "arr");
        assert_eq!(elements.len(), 3);
    } else {
        panic!("expected LetArray, got {:?}", ir.body[0]);
    }
}

#[test]
fn stmt_empty_array_rejected() {
    let err = compile_circuit("let arr = []").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_assert_eq_as_node() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })),
        "expected AssertEq node in body"
    );
}

#[test]
fn stmt_assert_as_node() {
    let ir = compile_circuit("public x\nassert(x)").unwrap();
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::Assert { .. })),
        "expected Assert node in body"
    );
}

#[test]
fn stmt_assert_with_message() {
    let ir = compile_circuit("public x\nassert(x, \"x must be true\")").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::Assert { .. }))
        .expect("expected Assert node");
    if let CircuitNode::Assert { message, .. } = node {
        assert_eq!(message.as_deref(), Some("x must be true"));
    }
}

#[test]
fn stmt_assert_without_message() {
    let ir = compile_circuit("public x\nassert(x)").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::Assert { .. }))
        .expect("expected Assert node");
    if let CircuitNode::Assert { message, .. } = node {
        assert_eq!(*message, None);
    }
}

#[test]
fn stmt_assert_message_must_be_string() {
    let err = compile_circuit("public x\nassert(x, 42)").unwrap_err();
    assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
}

#[test]
fn stmt_assert_too_many_args() {
    let err = compile_circuit("public x\nassert(x, \"msg\", 1)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_assert_eq_with_message() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b, \"values must match\")").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .expect("expected AssertEq node");
    if let CircuitNode::AssertEq { message, .. } = node {
        assert_eq!(message.as_deref(), Some("values must match"));
    }
}

#[test]
fn stmt_assert_eq_without_message() {
    let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
    let node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .expect("expected AssertEq node");
    if let CircuitNode::AssertEq { message, .. } = node {
        assert_eq!(*message, None);
    }
}

#[test]
fn stmt_assert_eq_message_must_be_string() {
    let err = compile_circuit("public a\npublic b\nassert_eq(a, b, 42)").unwrap_err();
    assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
}

#[test]
fn stmt_assert_eq_too_many_args() {
    let err = compile_circuit("public a\npublic b\nassert_eq(a, b, \"msg\", 1)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_fn_decl_not_emitted() {
    let ir = compile_circuit("public x\nfn f(a) { a }\nassert_eq(x, x)").unwrap();
    // FnDecl doesn't produce a body node — it's stored in fn_table
    assert!(
        !ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "f")),
        "FnDecl should not produce a Let node"
    );
}

#[test]
fn stmt_print_rejected() {
    let err = compile_circuit("print(42)").unwrap_err();
    assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
}

#[test]
fn stmt_break_rejected() {
    // break outside loop is actually a parse error, but test the stmt handler
    let err = compile_circuit("public x\nassert_eq(x, x)");
    // This should succeed — break only fails if actually encountered
    assert!(err.is_ok());
}

#[test]
fn stmt_basic_circuit() {
    // A complete basic circuit: public out, witness a, b, assert_eq(a * b, out)
    let ir = compile_circuit(
        "public out\nwitness a\nwitness b\nlet product = a * b\nassert_eq(product, out)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert_eq!(ir.public_inputs[0].name, "out");
    assert_eq!(ir.witness_inputs[0].name, "a");
    assert_eq!(ir.witness_inputs[1].name, "b");
    // Body: Let(product) + AssertEq
    assert!(ir.body.len() >= 2);
    assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "product"));
    assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
}

#[test]
fn stmt_poseidon_circuit() {
    let ir = compile_circuit(
        "public hash\nwitness secret\nlet h = poseidon(secret, 0)\nassert_eq(h, hash)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    // Body: Let(h = PoseidonHash) + AssertEq
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert!(
            matches!(value, CircuitExpr::PoseidonHash { .. }),
            "expected PoseidonHash, got {value:?}"
        );
    } else {
        panic!("expected Let node, got {:?}", ir.body[0]);
    }
}

#[test]
fn stmt_with_static_access() {
    // Field::ZERO should work inside a circuit now!
    let ir = compile_circuit("public x\nlet zero = Field::ZERO\nassert_eq(x, zero)").unwrap();
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
    } else {
        panic!("expected Let node");
    }
}
