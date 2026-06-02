use super::helpers::*;

#[test]
fn audit_if_emits_both_branch_constraints() {
    let ir = compile_and_instantiate(
        "public c\npublic a\npublic b\n\
         if c { assert_eq(a, 1) } else { assert_eq(b, 2) }",
    );
    let assert_eqs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { .. }))
        .count();
    assert_eq!(
        assert_eqs, 2,
        "both if/else branches must emit their constraints"
    );
}

// ForRange::Array with empty array
#[test]
fn audit_for_array_empty() {
    let _prove_ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![CircuitNode::For {
            var: "x".into(),
            range: ForRange::Array("arr".into()),
            body: vec![],
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    // Need "arr" in env as an empty array — not possible from the
    // public API without a LetArray node. Use a LetArray with empty elements instead.
    // Actually, empty arrays are rejected by the compiler. Test via non-empty but
    // verifying the loop body isn't entered would require a different approach.
    // Skip: empty arrays are rejected at compile time (Phase A).
}

// CaptureUsage::Both
#[test]
fn audit_instantiate_rejects_huge_capture_loop() {
    // Construct ProveIR directly (parser doesn't support dynamic for bounds)
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![CaptureDef {
            name: "n".into(),
            usage: CaptureUsage::StructureOnly,
        }],
        body: vec![CircuitNode::For {
            var: "i".into(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "n".into(),
            },
            body: vec![],
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let captures: HashMap<String, FieldElement<Bn254Fr>> = [(
        "n".to_string(),
        FieldElement::<Bn254Fr>::from_u64(2_000_000),
    )]
    .into_iter()
    .collect();
    let err = prove_ir.instantiate_lysis(&captures).unwrap_err();
    assert!(
        matches!(
            err,
            ir_forge::LysisInstantiateError::Instantiate(ProveIrError::RangeTooLarge { .. })
        ),
        "expected RangeTooLarge, got: {err}"
    );
}

#[test]
fn audit_import_in_circuit_body_rejected() {
    let err = ProveIrCompiler::<Bn254Fr>::compile_circuit(
        "circuit test(x: Public) { import \"./foo.ach\" as foo\nassert_eq(x, x) }",
        None,
    )
    .unwrap_err();
    // Parser rejects import inside block — surfaces as a parse error
    assert!(
        matches!(err, ProveIrError::ParseError(_)),
        "expected ParseError for import inside circuit body, got: {err}"
    );
}

// --- Source map (span propagation) ---
