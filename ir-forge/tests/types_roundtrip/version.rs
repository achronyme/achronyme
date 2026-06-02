use super::*;

#[test]
fn v3_and_v4_rejected_with_recompile_message() {
    let ir = ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
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
        component_bodies: Default::default(),
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
        component_bodies: Default::default(),
    };
    let mut bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
    bytes[5] = 0xFF; // invalid prime byte
    let err = ProveIR::from_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("PrimeId"),
        "error should mention PrimeId: {err}"
    );
}
