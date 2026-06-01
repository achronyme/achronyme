use super::*;

// =====================================================================
// Capture classification (end-to-end via compile())
// =====================================================================

/// Helper: compile a prove block body with outer scope captures (all scalar).
fn compile_prove_block(source: &str, outer_vars: &[&str]) -> Result<ProveIR, ProveIrError> {
    let outer = OuterScope {
        values: outer_vars
            .iter()
            .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
            .collect(),
        ..Default::default()
    };
    ProveIrCompiler::<Bn254Fr>::compile_prove_block(source, &outer)
}

#[test]
fn capture_classification_end_to_end() {
    // secret is used in constraint (poseidon), hash is declared public
    let ir = compile_prove_block(
        "public hash\nassert_eq(poseidon(secret, 0), hash)",
        &["secret", "hash"],
    )
    .unwrap();
    // hash is declared as public input, so not a capture
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "hash");
    // secret is captured and used in constraint
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "secret");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}

#[test]
fn no_captures_in_self_contained_circuit() {
    // ach circuit mode: no outer scope, no captures
    let ir = compile_circuit("public out\nwitness a\nwitness b\nassert_eq(a * b, out)").unwrap();
    assert!(ir.captures.is_empty());
}
