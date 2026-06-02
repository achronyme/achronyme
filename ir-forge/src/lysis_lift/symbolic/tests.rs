use memory::{Bn254Fr, FieldElement};

use super::*;
use crate::{ExtendedInstruction, TemplateId};
use ir_core::{Instruction, SsaVar, Visibility, WitnessCallBody};

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i.into())
}

fn push_const(body: &mut Vec<ExtendedInstruction<Bn254Fr>>, result: u32, v: u64) {
    body.push(
        Instruction::Const {
            result: ssa(result),
            value: fe(v),
        }
        .into(),
    );
}

#[test]
fn empty_body_empty_tree() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let t = symbolic_emit(&body, &[]);
    assert!(t.is_empty());
    assert!(t.body_order.is_empty());
    assert_eq!(t.n_slots, 0);
}

#[test]
fn no_bindings_emits_only_literal_consts() {
    let mut body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    push_const(&mut body, 0, 42);
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    assert_eq!(t.body_order.len(), 1);
    let node = &t.nodes[t.body_order[0] as usize];
    match node {
        SymbolicNode::Const { value, from_slot } => {
            assert_eq!(*value, fe(42));
            assert!(from_slot.is_none());
        }
        _ => panic!("expected literal Const"),
    }
}

#[test]
fn binding_produces_slot_tagged_const_at_top() {
    // Empty body, one binding → one slot at index 0.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let t = symbolic_emit(&body, &[(ssa(0), fe(5))]);
    assert_eq!(t.n_slots, 1);
    assert_eq!(t.nodes.len(), 1);
    match &t.nodes[0] {
        SymbolicNode::Const {
            value,
            from_slot: Some(SlotId(0)),
        } => {
            assert_eq!(*value, fe(5));
        }
        _ => panic!("expected slot-tagged Const at index 0"),
    }
}

#[test]
fn operand_referencing_bound_var_resolves_to_slot() {
    // body: Mul(r0, r0) where r0 is the loop var bound to fe(3).
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let t = symbolic_emit(&body, &[(ssa(0), fe(3))]);
    // Nodes: [0] slot-Const, [1] Op(Mul, [0, 0]).
    assert_eq!(t.nodes.len(), 2);
    match &t.nodes[1] {
        SymbolicNode::Op { tag, operands } => {
            assert_eq!(*tag, OpTag::Mul);
            assert_eq!(operands.as_slice(), &[0, 0]);
        }
        _ => panic!(),
    }
    assert_eq!(t.body_order, vec![1]);
}

#[test]
fn operand_to_outer_scope_var_becomes_outer_ref() {
    // body: Add(r99 /* outer */, r0 /* literal const */).
    let mut body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    push_const(&mut body, 0, 7);
    body.push(
        Instruction::Add {
            result: ssa(10),
            lhs: ssa(99), // outer scope
            rhs: ssa(0),
        }
        .into(),
    );
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    // Nodes: [0] literal Const, [1] OuterRef(99), [2] Op(Add, [1,0]).
    assert_eq!(t.nodes.len(), 3);
    assert!(matches!(
        &t.nodes[1],
        SymbolicNode::OuterRef(v) if *v == ssa(99)
    ));
    match &t.nodes[2] {
        SymbolicNode::Op { tag, operands } => {
            assert_eq!(*tag, OpTag::Add);
            assert_eq!(operands.as_slice(), &[1, 0]);
        }
        _ => panic!(),
    }
}

#[test]
fn outer_ref_is_dedup_per_ssavar() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Add {
            result: ssa(10),
            lhs: ssa(99),
            rhs: ssa(99),
        }
        .into(),
        Instruction::Mul {
            result: ssa(11),
            lhs: ssa(99),
            rhs: ssa(10),
        }
        .into(),
    ];
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    let outer_refs: Vec<_> = t
        .nodes
        .iter()
        .filter(|n| matches!(n, SymbolicNode::OuterRef(v) if *v == ssa(99)))
        .collect();
    assert_eq!(outer_refs.len(), 1, "same outer SsaVar must dedup");
}

#[test]
fn probe_twice_differs_only_in_slot_value() {
    // body: Add(iter_var, Const(5)). Probe at 0 and 1.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Const {
            result: ssa(1),
            value: fe(5),
        }
        .into(),
        Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }
        .into(),
    ];
    let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
    let b = symbolic_emit(&body, &[(ssa(0), fe(1))]);

    // Structural shape matches.
    assert_eq!(a.nodes.len(), b.nodes.len());
    assert_eq!(a.body_order, b.body_order);

    // Slot at index 0 differs in value, identical slot_id.
    match (&a.nodes[0], &b.nodes[0]) {
        (
            SymbolicNode::Const {
                value: va,
                from_slot: Some(sa),
            },
            SymbolicNode::Const {
                value: vb,
                from_slot: Some(sb),
            },
        ) => {
            assert_eq!(sa, sb);
            assert_ne!(va, vb);
        }
        _ => panic!(),
    }
    // Literal Const at index 1 is untouched.
    match (&a.nodes[1], &b.nodes[1]) {
        (
            SymbolicNode::Const {
                value: va,
                from_slot: None,
            },
            SymbolicNode::Const {
                value: vb,
                from_slot: None,
            },
        ) => {
            assert_eq!(va, vb);
            assert_eq!(*va, fe(5));
        }
        _ => panic!(),
    }
}

#[test]
fn decompose_bind_all_bit_results_to_same_node() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Witness,
        }
        .into(),
        Instruction::Decompose {
            result: ssa(0),
            bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
            operand: ssa(0),
            num_bits: 4,
        }
        .into(),
    ];
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    // Nodes: [0] Input, [1] Op(Decompose(4), [0]).
    assert_eq!(t.nodes.len(), 2);
    match &t.nodes[1] {
        SymbolicNode::Op { tag, .. } => assert_eq!(*tag, OpTag::Decompose(4)),
        _ => panic!(),
    }
}

#[test]
fn witness_call_hashes_program_bytes() {
    let a: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::Plain(
        Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![ssa(0)],
            inputs: vec![],
            program_bytes: vec![0xAA, 0xBB],
        })),
    )];
    let b: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::Plain(
        Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![ssa(0)],
            inputs: vec![],
            program_bytes: vec![0xAA, 0xBB],
        })),
    )];
    let c: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::Plain(
        Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![ssa(0)],
            inputs: vec![],
            program_bytes: vec![0xCC, 0xDD],
        })),
    )];
    let ta = symbolic_emit::<Bn254Fr>(&a, &[]);
    let tb = symbolic_emit::<Bn254Fr>(&b, &[]);
    let tc = symbolic_emit::<Bn254Fr>(&c, &[]);
    let tag = |t: &SymbolicTree<Bn254Fr>| match &t.nodes[0] {
        SymbolicNode::Op { tag, .. } => *tag,
        _ => panic!(),
    };
    assert_eq!(tag(&ta), tag(&tb), "same bytes → same tag");
    assert_ne!(tag(&ta), tag(&tc), "different bytes → different tag");
}

#[test]
fn nested_loop_becomes_opaque_marker() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 4,
        body: vec![],
    }];
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    assert_eq!(t.nodes.len(), 1);
    assert!(matches!(&t.nodes[0], SymbolicNode::NestedLoop));
}

#[test]
fn template_call_carries_id_and_capture_operands() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }
        .into(),
        ExtendedInstruction::TemplateCall {
            template_id: TemplateId(7),
            captures: vec![ssa(0), ssa(99)],
            outputs: vec![ssa(10), ssa(11)],
        },
    ];
    let t = symbolic_emit::<Bn254Fr>(&body, &[]);
    // Nodes: [0] literal Const, [1] OuterRef(99), [2] TemplateCall.
    let call_idx = t.body_order[1];
    match &t.nodes[call_idx as usize] {
        SymbolicNode::TemplateCall {
            template_id,
            capture_operands,
            n_outputs,
        } => {
            assert_eq!(*template_id, TemplateId(7));
            assert_eq!(*n_outputs, 2);
            assert_eq!(capture_operands.as_slice(), &[0, 1]);
        }
        _ => panic!(),
    }
}

#[test]
fn two_probes_preserve_node_count_and_order() {
    // Sanity: a body of N top-level statements always yields
    // body_order.len() == N regardless of probe value. (Slot
    // pool entries don't count toward body_order.)
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Const {
            result: ssa(1),
            value: fe(10),
        }
        .into(),
        Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }
        .into(),
        Instruction::Mul {
            result: ssa(3),
            lhs: ssa(2),
            rhs: ssa(0),
        }
        .into(),
    ];
    let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
    let b = symbolic_emit(&body, &[(ssa(0), fe(5))]);
    assert_eq!(a.body_order, b.body_order);
    assert_eq!(a.body_order.len(), 3);
}

#[test]
fn symbolic_array_read_emits_array_read_node_and_binds_result() {
    // SymbolicArrayRead in a body where iter_var is bound — the
    // probe drives a slot-tagged Const, the read becomes an
    // ArrayRead node, and result_var binds to the same NodeIdx so
    // a downstream use within the body resolves to the read.
    use crate::ExtendedInstruction;
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::SymbolicArrayRead {
            result_var: ssa(10),
            array_slots: vec![ssa(20), ssa(21)],
            index_var: ssa(0),
            span: None,
        },
        // Downstream use of result_var (ssa(10)) — should resolve
        // to the ArrayRead's NodeIdx via ssa_to_idx.
        Instruction::Add {
            result: ssa(11),
            lhs: ssa(10),
            rhs: ssa(10),
        }
        .into(),
    ];
    let t = symbolic_emit(&body, &[(ssa(0), fe(0))]);

    // Locate the ArrayRead node.
    let read_idx = t
        .nodes
        .iter()
        .position(|n| matches!(n, SymbolicNode::ArrayRead { .. }))
        .expect("ArrayRead node missing");
    match &t.nodes[read_idx] {
        SymbolicNode::ArrayRead {
            array_anchor,
            index_operand: _,
        } => {
            assert_eq!(
                array_anchor.len(),
                2,
                "array_anchor carries one NodeIdx per slot"
            );
        }
        _ => unreachable!(),
    }

    // The downstream Add node's operands should both point at the
    // ArrayRead node — confirming result_var was bound there.
    let add_node = t
        .nodes
        .iter()
        .find(|n| {
            matches!(
                n,
                SymbolicNode::Op {
                    tag: OpTag::Add,
                    ..
                }
            )
        })
        .expect("Add node missing");
    match add_node {
        SymbolicNode::Op {
            tag: OpTag::Add,
            operands,
        } => {
            assert_eq!(
                operands.as_slice(),
                &[read_idx as NodeIdx, read_idx as NodeIdx]
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn symbolic_array_read_two_probes_match_only_in_index_slot() {
    // Same body, two probe values for iter_var — both produce
    // ArrayRead at the same body position with identical
    // array_anchor; only the index_operand chain's slot value
    // differs. (Mirror of the indexed-effect test in diff.rs.)
    use crate::ExtendedInstruction;
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicArrayRead {
        result_var: ssa(10),
        array_slots: vec![ssa(20), ssa(21), ssa(22)],
        index_var: ssa(0),
        span: None,
    }];
    let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
    let b = symbolic_emit(&body, &[(ssa(0), fe(2))]);

    assert_eq!(a.nodes.len(), b.nodes.len());
    assert_eq!(a.body_order, b.body_order);
    // The slot-tagged Const at index 0 differs in value, identical
    // slot id.
    match (&a.nodes[0], &b.nodes[0]) {
        (
            SymbolicNode::Const {
                value: va,
                from_slot: Some(sa),
            },
            SymbolicNode::Const {
                value: vb,
                from_slot: Some(sb),
            },
        ) => {
            assert_eq!(sa, sb);
            assert_ne!(va, vb);
        }
        _ => panic!("slot 0 must be slot-tagged Const"),
    }
}

#[test]
fn multiple_bindings_produce_multiple_slots() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let t = symbolic_emit(&body, &[(ssa(0), fe(1)), (ssa(1), fe(2))]);
    assert_eq!(t.n_slots, 2);
    assert_eq!(t.nodes.len(), 2);
    assert!(matches!(
        &t.nodes[0],
        SymbolicNode::Const {
            from_slot: Some(SlotId(0)),
            ..
        }
    ));
    assert!(matches!(
        &t.nodes[1],
        SymbolicNode::Const {
            from_slot: Some(SlotId(1)),
            ..
        }
    ));
}
