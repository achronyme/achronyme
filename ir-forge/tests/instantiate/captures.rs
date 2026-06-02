use super::helpers::*;

#[test]
fn instantiate_with_capture_as_witness() {
    let ir = compile_and_instantiate_with_captures(
        "public hash\nassert_eq(poseidon(secret, 0), hash)",
        &["secret", "hash"],
        &[("secret", 42)],
    );
    // secret is a capture classified as CircuitInput → witness Input
    let witness_inputs: Vec<&str> = ir
        .instructions
        .iter()
        .filter_map(|i| match i {
            Instruction::Input {
                name,
                visibility: Visibility::Witness,
                ..
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        witness_inputs.contains(&"secret"),
        "secret should be a witness input, got: {witness_inputs:?}"
    );
}

#[test]
fn instantiate_missing_capture_error() {
    // Construct a ProveIR that requires a capture "secret" but don't provide it
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![CaptureDef {
            name: "secret".into(),
            usage: CaptureUsage::CircuitInput,
        }],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let result = prove_ir.instantiate_lysis::<Bn254Fr>(&HashMap::new());
    assert!(result.is_err(), "should fail with missing capture");
}

// --- Comparison operators ---

#[test]
fn audit_capture_both_is_witness_input() {
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![ProveInputDecl {
            name: "out".into(),
            array_size: None,
            ir_type: IrType::Field,
        }],
        witness_inputs: vec![],
        captures: vec![CaptureDef {
            name: "n".into(),
            usage: CaptureUsage::Both,
        }],
        body: vec![
            // Use n structurally (in a WithCapture range)
            CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![],
                span: None,
            },
            // Use n in a constraint expression
            CircuitNode::AssertEq {
                lhs: CircuitExpr::Capture("n".into()),
                rhs: CircuitExpr::Input("out".into()),
                message: None,
                span: None,
            },
        ],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let captures: HashMap<String, FieldElement<Bn254Fr>> =
        [("n".to_string(), FieldElement::<Bn254Fr>::from_u64(3))]
            .into_iter()
            .collect();
    let ir = prove_ir.instantiate_lysis(&captures).unwrap();
    // n should be a witness Input (not just a Const)
    let witness_inputs: Vec<&str> = ir
        .instructions
        .iter()
        .filter_map(|i| match i {
            Instruction::Input {
                name,
                visibility: Visibility::Witness,
                ..
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        witness_inputs.contains(&"n"),
        "Both capture must be witness input, got: {witness_inputs:?}"
    );
}

// Type propagation verification
#[test]
fn audit_both_capture_emits_assert_eq() {
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![CaptureDef {
            name: "n".into(),
            usage: CaptureUsage::Both,
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
    let captures: HashMap<String, FieldElement<Bn254Fr>> =
        [("n".to_string(), FieldElement::<Bn254Fr>::from_u64(3))]
            .into_iter()
            .collect();
    let ir = prove_ir.instantiate_lysis(&captures).unwrap();
    // Should have at least one AssertEq constraining capture n to its constant
    let assert_eqs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { .. }))
        .count();
    assert!(
        assert_eqs >= 1,
        "Both capture must emit AssertEq for consistency, found {assert_eqs}"
    );
}

// D3: Import rejection — imports inside circuit body are rejected at parse time.
// With flat format removed, imports can only appear at program top-level (before
