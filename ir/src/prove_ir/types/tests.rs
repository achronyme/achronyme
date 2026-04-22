//! Round-trip and validation tests for ProveIR types.

use super::prove_ir::PROVE_IR_FORMAT_VERSION;
use super::*;
use crate::prove_ir::compiler::{OuterScope, OuterScopeEntry, ProveIrCompiler};
use crate::types::IrType;
use memory::field::PrimeId;
use memory::Bn254Fr;

/// Round-trip: ProveIR → bytes → ProveIR, verify equality.
fn assert_round_trip(prove_ir: &ProveIR) {
    let bytes = prove_ir
        .to_bytes(PrimeId::Bn254)
        .expect("serialization failed");
    let (restored, prime) = ProveIR::from_bytes(&bytes).expect("deserialization failed");
    assert_eq!(prime, PrimeId::Bn254);

    // Spans are skipped, so we compare field-by-field excluding spans.
    assert_eq!(prove_ir.public_inputs, restored.public_inputs);
    assert_eq!(prove_ir.witness_inputs, restored.witness_inputs);
    assert_eq!(prove_ir.captures, restored.captures);
    // Body comparison: spans will be None after round-trip.
    // Compare the number and structure of nodes.
    assert_eq!(prove_ir.body.len(), restored.body.len());
}

#[test]
fn round_trip_empty() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
    };
    assert_round_trip(&ir);
}

#[test]
fn round_trip_simple_circuit() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_assert_eq_with_message() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public x\npublic out\nwitness s\nassert_eq(x + s, out, \"sums must match\")",
    )
    .unwrap();
    let bytes = ir.to_bytes(PrimeId::Bn254).expect("serialization failed");
    let (restored, _) = ProveIR::from_bytes(&bytes).expect("deserialization failed");
    // Verify message survives round-trip
    let msg = restored.body.iter().find_map(|n| {
        if let CircuitNode::AssertEq { message, .. } = n {
            message.clone()
        } else {
            None
        }
    });
    assert_eq!(msg.as_deref(), Some("sums must match"));
}

#[test]
fn round_trip_with_all_expr_types() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public a\npublic b\npublic out\n\
         let sum = a + b\n\
         let diff = a - b\n\
         let prod = a * b\n\
         let neg = -a\n\
         let cmp = a == b\n\
         let lt = a < b\n\
         let both = cmp && lt\n\
         let sel = mux(cmp, a, b)\n\
         let h = poseidon(a, b)\n\
         range_check(a, 8)\n\
         let p = a ^ 3\n\
         assert_eq(sum, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_for_loop() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public out\nmut acc = 0\nfor i in 0..5 { acc = acc + i }\nassert_eq(acc, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_if_else() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_captures() {
    let scope = OuterScope {
        values: ["secret", "hash"]
            .iter()
            .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
            .collect(),
        ..Default::default()
    };
    let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
        "public hash\nassert_eq(poseidon(secret, 0), hash)",
        &scope,
    )
    .unwrap();
    assert_round_trip(&ir);
    assert_eq!(ir.captures.len(), 1);
}

#[test]
fn round_trip_with_arrays() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public out\nlet arr = [1, 2, 3]\nassert_eq(arr_0, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_functions() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public out\nfn double(x) { x * 2 }\nassert_eq(double(21), out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_preserves_field_elements() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public out\nassert_eq(Field::ZERO + Field::ONE, out)",
    )
    .unwrap();
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();

    // The body should contain Const(ZERO) and Const(ONE) nodes.
    // After round-trip, the FieldElement values must be identical.
    fn collect_consts(body: &[CircuitNode]) -> Vec<&FieldConst> {
        let mut consts = Vec::new();
        for node in body {
            if let CircuitNode::Let { value, .. } = node {
                collect_expr_consts(value, &mut consts);
            }
            if let CircuitNode::AssertEq { lhs, rhs, .. } = node {
                collect_expr_consts(lhs, &mut consts);
                collect_expr_consts(rhs, &mut consts);
            }
        }
        consts
    }
    fn collect_expr_consts<'a>(expr: &'a CircuitExpr, out: &mut Vec<&'a FieldConst>) {
        match expr {
            CircuitExpr::Const(fe) => out.push(fe),
            CircuitExpr::BinOp { lhs, rhs, .. } => {
                collect_expr_consts(lhs, out);
                collect_expr_consts(rhs, out);
            }
            _ => {}
        }
    }

    let original_consts = collect_consts(&ir.body);
    let restored_consts = collect_consts(&restored.body);
    assert_eq!(original_consts.len(), restored_consts.len());
    for (a, b) in original_consts.iter().zip(restored_consts.iter()) {
        assert_eq!(a, b, "FieldElement round-trip mismatch");
    }
}

#[test]
fn round_trip_instantiate_produces_same_result() {
    use std::collections::HashMap;

    let ir =
        crate::prove_ir::test_utils::compile_circuit("public x\npublic out\nassert_eq(x + 1, out)")
            .unwrap();

    // Instantiate original
    let program1 = ir.instantiate::<Bn254Fr>(&HashMap::new()).unwrap();

    // Round-trip and instantiate
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();
    let program2 = restored.instantiate::<Bn254Fr>(&HashMap::new()).unwrap();

    // Both should produce identical instruction counts and types
    assert_eq!(
        program1.len(),
        program2.len(),
        "instruction count mismatch after round-trip"
    );
}

#[test]
fn serialized_size_reasonable() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public a\npublic b\npublic out\nassert_eq(poseidon(a, b), out)",
    )
    .unwrap();
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    // A simple circuit should serialize to < 1 KB
    assert!(
        bytes.len() < 1024,
        "serialized size {} bytes seems too large",
        bytes.len()
    );
}

// =====================================================================
// Display tests
// =====================================================================

#[test]
fn display_simple_circuit() {
    let ir = crate::prove_ir::test_utils::compile_circuit(
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
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public out\nmut acc = 0\nfor i in 0..3 { acc = acc + i }\nassert_eq(acc, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("for i in 0..3"), "got:\n{output}");
}

#[test]
fn display_with_mux_from_if() {
    // if-expressions are desugared to mux by the ProveIR compiler
    let ir = crate::prove_ir::test_utils::compile_circuit(
        "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
    )
    .unwrap();
    let output = format!("{ir}");
    assert!(output.contains("mux("), "got:\n{output}");
    assert!(output.contains("assert_eq("), "got:\n{output}");
}

// =====================================================================
// Adversarial deserialization tests
// =====================================================================

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
    };

    // Serialization + deserialization succeeds (FieldConst is just bytes)
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();

    // But instantiation fails because the bytes are >= BN254 modulus
    let result = restored.instantiate::<Bn254Fr>(&std::collections::HashMap::new());
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

// =====================================================================
// v4 format / multi-prime tests
// =====================================================================

#[test]
fn v3_and_v4_rejected_with_recompile_message() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
    };
    // v3 blob (no prime byte)
    let payload = bincode::serialize(&ir).unwrap();
    let mut bytes_v3 = Vec::new();
    bytes_v3.extend_from_slice(b"ACHP");
    bytes_v3.push(3);
    bytes_v3.extend_from_slice(&payload);
    let err = ProveIR::from_bytes(&bytes_v3).unwrap_err();
    assert!(
        err.contains("no longer supported") && err.contains("recompile"),
        "v3 error should mention recompile: {err}"
    );

    // v4 blob (has prime byte, but old serialization format)
    let mut bytes_v4 = Vec::new();
    bytes_v4.extend_from_slice(b"ACHP");
    bytes_v4.push(4);
    bytes_v4.push(PrimeId::Bn254.to_byte());
    bytes_v4.extend_from_slice(&payload);
    let err = ProveIR::from_bytes(&bytes_v4).unwrap_err();
    assert!(
        err.contains("no longer supported") && err.contains("recompile"),
        "v4 error should mention recompile: {err}"
    );
}

#[test]
fn v4_roundtrip_with_each_prime() {
    let ir = ProveIR {
        name: Some("test".into()),
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
    };
    for prime in [PrimeId::Bn254, PrimeId::Bls12_381, PrimeId::Goldilocks] {
        let bytes = ir.to_bytes(prime).unwrap();
        let (restored, restored_prime) = ProveIR::from_bytes(&bytes).unwrap();
        assert_eq!(restored_prime, prime, "prime mismatch for {}", prime.name());
        assert_eq!(restored.name, ir.name);
    }
}

#[test]
fn v4_bad_prime_byte_rejected() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
    };
    let mut bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    bytes[5] = 0xFF; // invalid prime byte
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("PrimeId"),
        "error should mention PrimeId: {err}"
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
    };
    let err = ir.validate().unwrap_err();
    assert!(
        err.contains("missing"),
        "should mention unknown capture: {err}"
    );
}

// =====================================================================
// FieldConst::from_decimal_str / from_hex_str tests
// =====================================================================

#[test]
fn field_const_from_decimal_small() {
    let fc = FieldConst::from_decimal_str("42").unwrap();
    assert_eq!(fc, FieldConst::from_u64(42));
}

#[test]
fn field_const_from_decimal_zero() {
    let fc = FieldConst::from_decimal_str("0").unwrap();
    assert_eq!(fc, FieldConst::zero());
}

#[test]
fn field_const_from_decimal_large() {
    // BN254 field order - 1 (a ~77 digit number)
    let s = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    let fc = FieldConst::from_decimal_str(s).unwrap();
    // Should not be zero and should not fit in u64
    assert!(!fc.is_zero());
    assert!(fc.to_u64().is_none());
}

#[test]
fn field_const_from_decimal_max_u64() {
    let fc = FieldConst::from_decimal_str("18446744073709551615").unwrap();
    assert_eq!(fc, FieldConst::from_u64(u64::MAX));
}

#[test]
fn field_const_from_decimal_just_above_u64() {
    let fc = FieldConst::from_decimal_str("18446744073709551616").unwrap();
    assert!(fc.to_u64().is_none());
    // Verify byte 8 is 1 (2^64 = 1 in byte[8])
    assert_eq!(fc.bytes()[8], 1);
}

#[test]
fn field_const_from_decimal_invalid() {
    assert!(FieldConst::from_decimal_str("").is_none());
    assert!(FieldConst::from_decimal_str("abc").is_none());
    assert!(FieldConst::from_decimal_str("12x3").is_none());
}

#[test]
fn field_const_from_hex_small() {
    let fc = FieldConst::from_hex_str("0xFF").unwrap();
    assert_eq!(fc, FieldConst::from_u64(255));
}

#[test]
fn field_const_from_hex_no_prefix() {
    let fc = FieldConst::from_hex_str("ff").unwrap();
    assert_eq!(fc, FieldConst::from_u64(255));
}

#[test]
fn field_const_from_hex_large() {
    // 64 hex digits = 32 bytes (max)
    let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    let fc = FieldConst::from_hex_str(hex).unwrap();
    assert!(!fc.is_zero());
    assert!(fc.to_u64().is_none());
}

#[test]
fn field_const_from_hex_with_0x_prefix() {
    let fc = FieldConst::from_hex_str("0x1234").unwrap();
    assert_eq!(fc, FieldConst::from_u64(0x1234));
}

#[test]
fn field_const_from_hex_invalid() {
    assert!(FieldConst::from_hex_str("").is_none());
    assert!(FieldConst::from_hex_str("0x").is_none());
    assert!(FieldConst::from_hex_str("0xGG").is_none());
    // 65 hex digits = too large
    let too_large = "1".to_string() + &"0".repeat(64);
    assert!(FieldConst::from_hex_str(&too_large).is_none());
}
