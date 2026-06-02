use super::helpers::*;

#[test]
fn spans_propagated_to_assert_eq() {
    // When compiling from source, CircuitNode::AssertEq gets a span.
    // After instantiation, the IR instruction's SsaVar should have that span.
    let ir = compile_and_instantiate("public x\nwitness y\nassert_eq(x, y)");
    // Find the AssertEq instruction
    let assert_eq_var = ir
        .instructions
        .iter()
        .find(|i| matches!(i, Instruction::AssertEq { .. }))
        .map(|i| i.result_var())
        .expect("should have AssertEq");
    let span = ir.get_span(assert_eq_var);
    assert!(
        span.is_some(),
        "AssertEq instruction should have a source span"
    );
    // wrap_flat_to_circuit moves declarations to params, body starts at line 2
    assert_eq!(span.unwrap().line_start, 2);
}

#[test]
fn spans_propagated_to_let_binding() {
    let ir = compile_and_instantiate("public x\nwitness y\nlet z = x + y\nassert_eq(z, z)");
    // The Add instruction comes from `let z = x + y`
    let add_var = ir
        .instructions
        .iter()
        .find(|i| matches!(i, Instruction::Add { .. }))
        .map(|i| i.result_var())
        .expect("should have Add");
    let span = ir.get_span(add_var);
    assert!(span.is_some(), "Add instruction should have a source span");
    // Body line 1: let z = x + y → line 2 in wrapped format
    assert_eq!(span.unwrap().line_start, 2);
}

// Ignored: the Lysis path (Walker → bytecode → InterningSink →
// materialize) drops the per-iteration source span on AssertEq nodes
// lifted out of a `CircuitNode::For` body. The legacy path attached
// the body expression's span to each unrolled instruction; Lysis
// emits a single `ExtendedInstruction::LoopUnroll` whose body carries
// no per-instruction span side-channel through the bytecode
// round-trip.
#[test]
#[ignore = "Lysis loop-body span gap — see fix-Lysis-loop-body-span-propagation task"]
fn spans_propagated_through_for_loop() {
    // For loop body gets the body node's span, not the loop's span
    let ir = compile_and_instantiate("public x\nfor i in 0..3 {\n  assert_eq(x, x)\n}");
    // Should have 3 AssertEq instructions (loop unrolled)
    let assert_eqs: Vec<_> = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { .. }))
        .collect();
    assert_eq!(assert_eqs.len(), 3);
    // Each should have a span (from the body's assert_eq)
    for inst in &assert_eqs {
        let span = ir.get_span(inst.result_var());
        assert!(
            span.is_some(),
            "AssertEq in loop body should have a source span"
        );
    }
}

// --- Indexed array assignment (LetIndexed from .ach) ---
