use super::*;

#[test]
fn adversarial_empty_bytes() {
    assert!(ProveIR::from_bytes(&[]).is_err());
}

#[test]
fn adversarial_too_short() {
    assert!(ProveIR::from_bytes(b"ACH").is_err());
}

#[test]
fn adversarial_wrong_magic() {
    assert!(ProveIR::from_bytes(b"EVIL\x01").is_err());
}

#[test]
fn adversarial_wrong_version() {
    let mut bytes = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    }
    .to_bytes(PrimeId::Bn254)
    .unwrap();
    bytes[4] = 99; // corrupt version byte
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("version"),
        "error should mention version: {err}"
    );
}

#[test]
fn adversarial_truncated_payload() {
    let bytes = ProveIR {
        name: None,
        public_inputs: vec![ProveInputDecl {
            name: "x".into(),
            array_size: None,
            ir_type: IrType::Field,
        }],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    }
    .to_bytes(PrimeId::Bn254)
    .unwrap();
    // Truncate the payload
    let truncated = &bytes[..bytes.len() / 2];
    assert!(ProveIR::from_bytes(truncated).is_err());
}

#[test]
fn adversarial_random_bytes() {
    // Version 99 is unsupported
    let garbage = b"ACHP\x63\xff\xff\xff\xff\xff\xff\xff\xff";
    assert!(ProveIR::from_bytes(garbage).is_err());
}

#[test]
fn adversarial_invalid_field_const_rejected_at_instantiation() {
    // FieldConst stores raw bytes — any [u8;32] is valid at the
    // serialization layer. But values >= modulus are rejected when
    // instantiation calls to_field::<F>().
    use memory::field::MODULUS;

    // Build bytes >= BN254 modulus
    let mut bad_bytes = [0u8; 32];
    for (i, limb) in MODULUS.iter().enumerate() {
        bad_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let bad_const = FieldConst::from_le_bytes(bad_bytes);

    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![CircuitNode::Let {
            name: "x".into(),
            value: CircuitExpr::Const(bad_const),
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    // Serialization + deserialization succeeds (FieldConst is just bytes)
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();

    // But instantiation fails because the bytes are >= BN254 modulus
    let result = restored.instantiate_lysis::<Bn254Fr>(&std::collections::HashMap::new());
    assert!(
        result.is_err(),
        "instantiation should reject FieldConst >= modulus"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("invalid") || err.contains("field"),
        "error should mention invalid field constant: {err}"
    );
}

// F4: PoseidonMany with < 2 args rejected after deserialization
#[test]
fn adversarial_poseidon_many_empty_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![CircuitNode::Expr {
            expr: CircuitExpr::PoseidonMany(vec![]),
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    // Serialize directly with bincode (bypass to_bytes header)
    let payload = bincode::serialize(&ir).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACHP");
    bytes.push(PROVE_IR_FORMAT_VERSION);
    bytes.push(PrimeId::Bn254.to_byte());
    bytes.extend_from_slice(&payload);
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("poseidon_many"),
        "should reject poseidon_many with 0 args: {err}"
    );
}

// F5: RangeCheck with invalid bits rejected
#[test]
fn adversarial_range_check_zero_bits_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![CircuitNode::Expr {
            expr: CircuitExpr::RangeCheck {
                value: Box::new(CircuitExpr::Const(FieldConst::from_u64(0))),
                bits: 0,
            },
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let payload = bincode::serialize(&ir).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACHP");
    bytes.push(PROVE_IR_FORMAT_VERSION);
    bytes.push(PrimeId::Bn254.to_byte());
    bytes.extend_from_slice(&payload);
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("range_check"),
        "should reject range_check bits=0: {err}"
    );
}

#[test]
fn adversarial_range_check_oversized_bits_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![CircuitNode::Expr {
            expr: CircuitExpr::RangeCheck {
                value: Box::new(CircuitExpr::Const(FieldConst::from_u64(0))),
                bits: 300,
            },
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let payload = bincode::serialize(&ir).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACHP");
    bytes.push(PROVE_IR_FORMAT_VERSION);
    bytes.push(PrimeId::Bn254.to_byte());
    bytes.extend_from_slice(&payload);
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("range_check"),
        "should reject range_check bits=300: {err}"
    );
}

// D4: ArraySize::Capture referencing unknown capture is rejected
#[test]
fn adversarial_array_size_unknown_capture_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![ProveInputDecl {
            name: "arr".into(),
            array_size: Some(ArraySize::Capture("ghost".into())),
            ir_type: IrType::Field,
        }],
        witness_inputs: vec![],
        captures: vec![], // no capture named "ghost"
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let err = ir.validate().unwrap_err();
    assert!(
        err.contains("ghost"),
        "should mention unknown capture: {err}"
    );
}

// D5: ForRange::WithCapture referencing unknown capture is rejected
#[test]
fn adversarial_for_range_unknown_capture_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![], // no capture named "missing"
        body: vec![CircuitNode::For {
            var: "i".into(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "missing".into(),
            },
            body: vec![],
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let err = ir.validate().unwrap_err();
    assert!(
        err.contains("missing"),
        "should mention unknown capture: {err}"
    );
}
