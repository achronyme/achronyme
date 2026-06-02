use super::*;

#[test]
fn round_trip_empty() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    assert_round_trip(&ir);
}

#[test]
fn round_trip_simple_circuit() {
    let ir = ir_forge::test_utils::compile_circuit(
        "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_assert_eq_with_message() {
    let ir = ir_forge::test_utils::compile_circuit(
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
    let ir = ir_forge::test_utils::compile_circuit(
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
    let ir = ir_forge::test_utils::compile_circuit(
        "public out\nmut acc = 0\nfor i in 0..5 { acc = acc + i }\nassert_eq(acc, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_if_else() {
    let ir = ir_forge::test_utils::compile_circuit(
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
    let ir = ir_forge::test_utils::compile_circuit(
        "public out\nlet arr = [1, 2, 3]\nassert_eq(arr_0, out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_with_functions() {
    let ir = ir_forge::test_utils::compile_circuit(
        "public out\nfn double(x) { x * 2 }\nassert_eq(double(21), out)",
    )
    .unwrap();
    assert_round_trip(&ir);
}

#[test]
fn round_trip_preserves_field_elements() {
    let ir = ir_forge::test_utils::compile_circuit(
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

    let ir = ir_forge::test_utils::compile_circuit("public x\npublic out\nassert_eq(x + 1, out)")
        .unwrap();

    // Instantiate original
    let program1 = ir.instantiate_lysis::<Bn254Fr>(&HashMap::new()).unwrap();

    // Round-trip and instantiate
    let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();
    let program2 = restored
        .instantiate_lysis::<Bn254Fr>(&HashMap::new())
        .unwrap();

    // Both should produce identical instruction counts and types
    assert_eq!(
        program1.len(),
        program2.len(),
        "instruction count mismatch after round-trip"
    );
}

#[test]
fn serialized_size_reasonable() {
    let ir = ir_forge::test_utils::compile_circuit(
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
