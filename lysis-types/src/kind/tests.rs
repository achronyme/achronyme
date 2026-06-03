use super::*;

fn n(idx: usize) -> NodeId {
    NodeId::from_zero_based(idx)
}

#[test]
fn result_points_at_named_slot() {
    let add = InstructionKind::<Bn254Fr>::Add {
        result: n(3),
        lhs: n(1),
        rhs: n(2),
    };
    assert_eq!(add.result(), n(3));
}

#[test]
fn witness_call_result_is_first_output() {
    let call = InstructionKind::<Bn254Fr>::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![n(10), n(11), n(12)],
        inputs: vec![n(1), n(2)],
        program_bytes: vec![0xAA; 8],
    }));
    assert_eq!(call.result(), n(10));
}

#[test]
fn side_effect_classification_matches_rfc() {
    let add = InstructionKind::<Bn254Fr>::Add {
        result: n(0),
        lhs: n(0),
        rhs: n(0),
    };
    assert!(!add.is_side_effect());

    let assert_eq = InstructionKind::<Bn254Fr>::AssertEq {
        result: n(0),
        lhs: n(0),
        rhs: n(0),
        message: None,
    };
    assert!(assert_eq.is_side_effect());

    let decompose = InstructionKind::<Bn254Fr>::Decompose {
        result: n(0),
        bit_results: vec![n(1), n(2)],
        operand: n(0),
        num_bits: 2,
    };
    assert!(decompose.is_side_effect());
}

#[test]
fn visibility_roundtrips_through_u8() {
    assert_eq!(Visibility::from_u8(0), Some(Visibility::Public));
    assert_eq!(Visibility::from_u8(1), Some(Visibility::Witness));
    assert_eq!(Visibility::from_u8(2), None);
    assert_eq!(Visibility::Public.as_u8(), 0);
    assert_eq!(Visibility::Witness.as_u8(), 1);
}

// Pin the enum's in-memory size so layout changes are intentional, not
// accidental. This kind flows through the lysis interner at chunk-emission
// scale (millions of entries on ECDSA-class circuits). `WitnessCall` is
// boxed; the in-place size is bounded by the next-largest variant
// (`AssertEq` with its `Option<String>` message, or `Decompose` with a
// `Vec` header plus three ids).
#[test]
fn instruction_kind_size_pinned() {
    assert_eq!(std::mem::size_of::<InstructionKind<Bn254Fr>>(), 56);
}
