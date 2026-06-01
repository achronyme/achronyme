use super::*;

// -----------------------------------------------------------------------
// Indexed array assignment: arr[i] = expr → LetIndexed
// -----------------------------------------------------------------------

#[test]
fn mut_array_decl() {
    let ir = compile_circuit("public out\nmut arr = [1, 2, 3]\nassert_eq(arr[0], out)").unwrap();
    // Should have a LetArray node
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::LetArray { name, .. } if name == "arr")),
        "expected LetArray for mut arr, body: {:#?}",
        ir.body
    );
}

#[test]
fn indexed_assignment_constant() {
    let ir =
        compile_circuit("public out\nmut arr = [0, 0, 0]\narr[1] = 42\nassert_eq(arr[1], out)")
            .unwrap();
    // Should have a LetIndexed node
    assert!(
        ir.body
            .iter()
            .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
        "expected LetIndexed for arr[1] = 42, body: {:#?}",
        ir.body
    );
}

#[test]
fn indexed_assignment_in_loop() {
    let ir = compile_circuit(
        "public out\n\
         mut arr = [0, 0, 0]\n\
         for i in 0..3 {\n\
             arr[i] = i * 2\n\
         }\n\
         assert_eq(arr[2], out)",
    )
    .unwrap();
    // For node body should contain LetIndexed
    let for_node = ir
        .body
        .iter()
        .find(|n| matches!(n, CircuitNode::For { .. }));
    assert!(for_node.is_some(), "expected For node");
    if let CircuitNode::For { body, .. } = for_node.unwrap() {
        assert!(
            body.iter()
                .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
            "expected LetIndexed inside for loop body, got: {body:#?}"
        );
    }
}

#[test]
fn indexed_assignment_immutable_array_rejected() {
    let err =
        compile_circuit("public out\nlet arr = [1, 2, 3]\narr[0] = 99\nassert_eq(arr[0], out)")
            .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("mut"), "error should mention mut, got: {msg}");
}

#[test]
fn indexed_assignment_scalar_rejected() {
    let err = compile_circuit("public out\nmut x = 5\nx[0] = 10\nassert_eq(x, out)").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("array") || msg.contains("scalar"),
        "error should mention type mismatch, got: {msg}"
    );
}
