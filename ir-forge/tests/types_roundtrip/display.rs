use super::*;

#[test]
fn display_simple_circuit() {
    let ir = ir_forge::test_utils::compile_circuit(
        "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("Public inputs:"), "got:\n{output}");
    assert!(output.contains("x: Field"), "got:\n{output}");
    assert!(output.contains("Witness inputs:"), "got:\n{output}");
    assert!(output.contains("s: Field"), "got:\n{output}");
    assert!(output.contains("assert_eq("), "got:\n{output}");
}

#[test]
fn display_with_captures() {
    let scope = OuterScope {
        values: [("secret", OuterScopeEntry::Scalar)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public hash\nassert_eq(poseidon(secret, 0), hash)",
        &scope,
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("Captures:"), "got:\n{output}");
    assert!(output.contains("secret"), "got:\n{output}");
    assert!(output.contains("poseidon("), "got:\n{output}");
}

#[test]
fn display_with_for_loop() {
    // Loop without a mut accumulator — the rolled `CircuitNode::For`
    // path is preserved, so the Display output keeps the literal
    // `for i in 0..N` syntax.
    let ir = ir_forge::test_utils::compile_circuit(
        "public out\nlet arr = [1, 2, 3]\nfor i in 0..3 { assert_eq(arr[i], arr[i]) }\nassert_eq(out, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("for i in 0..3"), "got:\n{output}");
}

#[test]
fn display_with_for_loop_eager_unrolled() {
    // Loop with a mut accumulator — eager-unrolls at lower time, so
    // no `CircuitNode::For` is in the IR. Display renders the
    // inlined per-iter SSA chain instead.
    let ir = ir_forge::test_utils::compile_circuit(
        "public out\nmut acc = 0\nfor i in 0..3 { acc = acc + i }\nassert_eq(acc, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(
        !output.contains("for i in"),
        "carry-set body should not render as a for loop. got:\n{output}"
    );
    assert!(
        output.contains("acc$v1") && output.contains("acc$v2") && output.contains("acc$v3"),
        "expected three SSA versions of acc in the unrolled output. got:\n{output}"
    );
}

#[test]
fn display_with_mux_from_if() {
    // if-expressions are desugared to mux by the ProveIR compiler
    let ir = ir_forge::test_utils::compile_circuit(
        "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("mux("), "got:\n{output}");
    assert!(output.contains("assert_eq("), "got:\n{output}");
}
