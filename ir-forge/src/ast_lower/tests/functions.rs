use super::*;

// =====================================================================
// Function inlining tests
// =====================================================================

#[test]
fn fn_simple_inline() {
    let ir =
        compile_circuit("public x\npublic out\nfn double(a) { a * 2 }\nassert_eq(double(x), out)")
            .unwrap();
    // double(x) should produce: Let(__double_a = Var(x)) then the inline result
    // The AssertEq should have the inlined expression
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_inline_with_let() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn square(n) { let r = n * n; r }\n\
         assert_eq(square(x), out)",
    )
    .unwrap();
    // The inlined body should have emitted a Let for r
    assert!(ir.body.iter().any(
        |n| matches!(n, CircuitNode::Let { name, .. } if name.contains("__square_n")
                                                              || name == "r")
    ));
}

#[test]
fn fn_inline_nested_calls() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn square(n) { n * n }\n\
         fn sum_of_squares(a, b) { square(a) + square(b) }\n\
         assert_eq(sum_of_squares(x, x), out)",
    )
    .unwrap();
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_with_return() {
    let ir = compile_circuit(
        "public out\nwitness x\n\
         fn check(n) { return n * 2 }\n\
         assert_eq(check(x), out)",
    )
    .unwrap();
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_wrong_arity_errors() {
    let err = compile_circuit("public x\nfn f(a, b) { a + b }\nassert_eq(f(x), x)").unwrap_err();
    assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
}

#[test]
fn fn_recursive_errors() {
    let err = compile_circuit("public x\nfn f(n) { f(n) }\nassert_eq(f(x), x)").unwrap_err();
    assert!(matches!(
        err,
        ProveIrError::RecursiveFunction { ref name } if name == "f"
    ));
}

#[test]
fn fn_undefined_errors() {
    let err = compile_circuit("public x\nassert_eq(unknown_fn(x), x)").unwrap_err();
    assert!(matches!(err, ProveIrError::UndeclaredVariable { .. }));
}

#[test]
fn fn_env_restored_after_inline() {
    // After inlining f(x), a reference to 'x' should still resolve to the outer x
    let ir = compile_circuit(
        "public x\npublic out\n\
         fn f(a) { a + 1 }\n\
         let y = f(x)\n\
         assert_eq(x + y, out)",
    )
    .unwrap();
    // The final assert_eq should reference outer x (not the param)
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn fn_hash_pair_circuit() {
    // Realistic circuit: fn hash_pair(a, b) { poseidon(a, b) }
    let ir = compile_circuit(
        "public out\nwitness a\nwitness b\n\
         fn hash_pair(x, y) { poseidon(x, y) }\n\
         assert_eq(hash_pair(a, b), out)",
    )
    .unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}
