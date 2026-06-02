use ir_core::{Instruction, SsaVar, Visibility as IrVisibility};
use lysis_types::WitnessCallBody as LysisWitnessCallBody;
use memory::{Bn254Fr, FieldElement};

use super::*;

fn node(i: usize) -> lysis_types::NodeId {
    lysis_types::NodeId::from_zero_based(i)
}

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

#[test]
fn node_id_to_ssa_var_preserves_zero_based_index() {
    assert_eq!(ssa_var_from_node_id(node(0)), SsaVar(0));
    assert_eq!(ssa_var_from_node_id(node(5)), SsaVar(5));
    assert_eq!(ssa_var_from_node_id(node(42)), SsaVar(42));
}

#[test]
fn const_variant_round_trips() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::Const {
        result: node(3),
        value: fe(7),
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::Const { result, value } => {
            assert_eq!(result, SsaVar(3));
            assert_eq!(value, fe(7));
        }
        _ => panic!("expected Const"),
    }
}

#[test]
fn add_variant_maps_operands() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::Add {
        result: node(10),
        lhs: node(1),
        rhs: node(2),
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::Add { result, lhs, rhs } => {
            assert_eq!(result, SsaVar(10));
            assert_eq!(lhs, SsaVar(1));
            assert_eq!(rhs, SsaVar(2));
        }
        _ => panic!("expected Add"),
    }
}

#[test]
fn input_variant_preserves_name_and_visibility() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::Input {
        result: node(0),
        name: "x".into(),
        visibility: lysis_types::Visibility::Witness,
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::Input {
            result,
            name,
            visibility,
        } => {
            assert_eq!(result, SsaVar(0));
            assert_eq!(name, "x");
            assert_eq!(visibility, IrVisibility::Witness);
        }
        _ => panic!("expected Input"),
    }
}

#[test]
fn decompose_maps_bit_results_vec() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::Decompose {
        result: node(0),
        bit_results: vec![node(1), node(2), node(3), node(4)],
        operand: node(0),
        num_bits: 4,
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::Decompose {
            result,
            bit_results,
            operand,
            num_bits,
        } => {
            assert_eq!(result, SsaVar(0));
            assert_eq!(operand, SsaVar(0));
            assert_eq!(num_bits, 4);
            assert_eq!(
                bit_results,
                vec![SsaVar(1), SsaVar(2), SsaVar(3), SsaVar(4)]
            );
        }
        _ => panic!("expected Decompose"),
    }
}

#[test]
fn witness_call_maps_outputs_inputs_and_bytes() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::WitnessCall(Box::new(LysisWitnessCallBody {
        outputs: vec![node(7), node(8)],
        inputs: vec![node(1), node(2), node(3)],
        program_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }));
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::WitnessCall(call) => {
            assert_eq!(call.outputs, vec![SsaVar(7), SsaVar(8)]);
            assert_eq!(call.inputs, vec![SsaVar(1), SsaVar(2), SsaVar(3)]);
            assert_eq!(call.program_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
        _ => panic!("expected WitnessCall"),
    }
}

#[test]
fn bounded_variants_carry_bitwidth() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::IsLtBounded {
        result: node(0),
        lhs: node(1),
        rhs: node(2),
        bitwidth: 8,
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::IsLtBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => {
            assert_eq!(result, SsaVar(0));
            assert_eq!(lhs, SsaVar(1));
            assert_eq!(rhs, SsaVar(2));
            assert_eq!(bitwidth, 8);
        }
        _ => panic!("expected IsLtBounded"),
    }
}

#[test]
fn intmod_carries_max_bits() {
    let k = lysis_types::InstructionKind::<Bn254Fr>::IntMod {
        result: node(0),
        lhs: node(1),
        rhs: node(2),
        max_bits: 32,
    };
    let ir = instruction_from_kind(&k);
    match ir {
        Instruction::IntMod {
            result,
            lhs,
            rhs,
            max_bits,
        } => {
            assert_eq!(result, SsaVar(0));
            assert_eq!(lhs, SsaVar(1));
            assert_eq!(rhs, SsaVar(2));
            assert_eq!(max_bits, 32);
        }
        _ => panic!("expected IntMod"),
    }
}

#[test]
fn owned_matches_ref_on_heap_bearing_variants() {
    // Pin: instruction_from_kind_owned produces structurally identical
    // output to instruction_from_kind for every variant that carries
    // String / Vec<u8> / Vec<NodeId> heap data - the streaming
    // pipeline relies on this equivalence.
    let cases: Vec<lysis_types::InstructionKind<Bn254Fr>> = vec![
        lysis_types::InstructionKind::Input {
            result: node(0),
            name: "alpha".into(),
            visibility: lysis_types::Visibility::Public,
        },
        lysis_types::InstructionKind::AssertEq {
            result: node(0),
            lhs: node(1),
            rhs: node(2),
            message: Some("must be equal".into()),
        },
        lysis_types::InstructionKind::Assert {
            result: node(0),
            operand: node(3),
            message: Some("bool".into()),
        },
        lysis_types::InstructionKind::Decompose {
            result: node(0),
            bit_results: vec![node(1), node(2), node(3), node(4)],
            operand: node(0),
            num_bits: 4,
        },
        lysis_types::InstructionKind::WitnessCall(Box::new(LysisWitnessCallBody {
            outputs: vec![node(7), node(8)],
            inputs: vec![node(1), node(2), node(3)],
            program_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        })),
    ];
    for k in cases {
        let by_ref = instruction_from_kind(&k);
        let by_val = instruction_from_kind_owned(k);
        assert_eq!(format!("{by_ref:?}"), format!("{by_val:?}"));
    }
}

#[test]
fn visibility_round_trip() {
    let pk = lysis_types::InstructionKind::<Bn254Fr>::Input {
        result: node(0),
        name: "p".into(),
        visibility: lysis_types::Visibility::Public,
    };
    let wk = lysis_types::InstructionKind::<Bn254Fr>::Input {
        result: node(0),
        name: "w".into(),
        visibility: lysis_types::Visibility::Witness,
    };
    match instruction_from_kind(&pk) {
        Instruction::Input { visibility, .. } => {
            assert_eq!(visibility, IrVisibility::Public);
        }
        _ => panic!(),
    }
    match instruction_from_kind(&wk) {
        Instruction::Input { visibility, .. } => {
            assert_eq!(visibility, IrVisibility::Witness);
        }
        _ => panic!(),
    }
}
