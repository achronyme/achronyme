use std::collections::{HashMap, HashSet};

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};
use memory::{Bn254Fr, FieldElement};

use super::labels::format_field;
use super::*;

fn simple_program() -> IrProgram<Bn254Fr> {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    // %0 = Input("x", public)
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    // %1 = Input("y", witness)
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    // %2 = Mul(%0, %1)
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    prog.set_name(v2, "product".into());
    // %3 = AssertEq(%2, %0)
    let v3 = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: v3,
        lhs: v2,
        rhs: v0,
        message: Some("product must equal x".into()),
    });
    prog
}

#[test]
fn graph_has_correct_node_count() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(graph.nodes.len(), 4);
    assert_eq!(graph.metadata.n_public, 1);
    assert_eq!(graph.metadata.n_witness, 1);
    assert_eq!(graph.metadata.n_instructions, 4);
}

#[test]
fn edges_from_def_use_chains() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    // Mul(%0, %1) → edges from node 0 and node 1 to node 2
    let mul_inputs: Vec<_> = graph.edges.iter().filter(|e| e.to_node == 2).collect();
    assert_eq!(mul_inputs.len(), 2);
    let from_nodes: HashSet<usize> = mul_inputs.iter().map(|e| e.from_node).collect();
    assert!(from_nodes.contains(&0)); // x
    assert!(from_nodes.contains(&1)); // y

    // AssertEq(%2, %0) → edges from node 2 and node 0 to node 3
    let assert_inputs: Vec<_> = graph.edges.iter().filter(|e| e.to_node == 3).collect();
    assert_eq!(assert_inputs.len(), 2);
    let from_nodes: HashSet<usize> = assert_inputs.iter().map(|e| e.from_node).collect();
    assert!(from_nodes.contains(&0)); // x
    assert!(from_nodes.contains(&2)); // product
}

#[test]
fn witness_values_annotated() {
    let prog = simple_program();
    let mut witness = HashMap::new();
    witness.insert(SsaVar(0), FieldElement::from_u64(6));
    witness.insert(SsaVar(1), FieldElement::from_u64(7));
    witness.insert(SsaVar(2), FieldElement::from_u64(42));

    let graph = build_inspector_graph(
        &prog,
        &witness,
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(graph.nodes[0].value.as_deref(), Some("6"));
    assert_eq!(graph.nodes[1].value.as_deref(), Some("7"));
    assert_eq!(graph.nodes[2].value.as_deref(), Some("42"));
}

#[test]
fn node_labels() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(graph.nodes[0].label, "Input(x, public)");
    assert_eq!(graph.nodes[1].label, "Input(y, witness)");
    assert_eq!(graph.nodes[2].label, "Mul (product)");
    assert_eq!(graph.nodes[3].label, "AssertEq(\"product must equal x\")");
}

#[test]
fn node_kinds() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(graph.nodes[0].kind, NodeKind::Input);
    assert_eq!(graph.nodes[1].kind, NodeKind::Input);
    assert_eq!(graph.nodes[2].kind, NodeKind::Mul);
    assert_eq!(graph.nodes[3].kind, NodeKind::AssertEq);
}

#[test]
fn failed_node_marked() {
    let prog = simple_program();
    let mut failed = HashMap::new();
    failed.insert(3, Some("mismatch".into())); // AssertEq failed

    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &failed,
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(
        graph.nodes[3].status,
        NodeStatus::Failed {
            message: Some("mismatch".into())
        }
    );
}

#[test]
fn failure_path_traced_backward() {
    let prog = simple_program();
    let mut failed = HashMap::new();
    failed.insert(3, None); // AssertEq(%2, %0) failed

    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &failed,
        &HashMap::new(),
        None,
        None,
        None,
    );

    // Node 3 is Failed
    assert!(matches!(graph.nodes[3].status, NodeStatus::Failed { .. }));

    // Node 2 (Mul, operand of AssertEq) should be OnFailurePath at distance 1
    assert_eq!(
        graph.nodes[2].status,
        NodeStatus::OnFailurePath { distance: 1 }
    );

    // Nodes 0 and 1 (inputs, operands of Mul) should be at distance 2
    // Node 0 is also a direct operand of AssertEq, so it could be distance 1
    // BFS will find the shortest path: node 0 is at distance 1 (direct operand of 3)
    assert_eq!(
        graph.nodes[0].status,
        NodeStatus::OnFailurePath { distance: 1 }
    );
    // Node 1 is only reachable via node 2, so distance 2
    assert_eq!(
        graph.nodes[1].status,
        NodeStatus::OnFailurePath { distance: 2 }
    );
}

#[test]
fn constraint_counts_in_nodes() {
    let prog = simple_program();
    let mut counts = HashMap::new();
    counts.insert(2, 1); // Mul = 1 constraint
    counts.insert(3, 1); // AssertEq = 1 constraint

    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &counts,
        None,
        None,
        None,
    );
    assert_eq!(graph.nodes[0].constraint_count, 0); // Input
    assert_eq!(graph.nodes[1].constraint_count, 0); // Input
    assert_eq!(graph.nodes[2].constraint_count, 1); // Mul
    assert_eq!(graph.nodes[3].constraint_count, 1); // AssertEq
    assert_eq!(graph.metadata.total_constraints, 2);
}

#[test]
fn format_field_small() {
    assert_eq!(format_field(&FieldElement::<Bn254Fr>::ZERO), "0");
    assert_eq!(format_field(&FieldElement::<Bn254Fr>::ONE), "1");
    assert_eq!(format_field(&FieldElement::<Bn254Fr>::from_u64(42)), "42");
    assert_eq!(
        format_field(&FieldElement::<Bn254Fr>::from_u64(u64::MAX)),
        u64::MAX.to_string()
    );
}

#[test]
fn metadata_has_circuit_name() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        Some("proof_of_membership"),
    );
    assert_eq!(graph.metadata.name, "proof_of_membership");
}

#[test]
fn metadata_default_name() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );
    assert_eq!(graph.metadata.name, "<anonymous>");
}

#[test]
fn source_code_and_prove_ir_text_included() {
    let prog = simple_program();
    let graph = build_inspector_graph(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        Some("let x = 1".into()),
        Some("ProveIR { ... }".into()),
        None,
    );
    assert_eq!(graph.source_code.as_deref(), Some("let x = 1"));
    assert_eq!(graph.prove_ir_text.as_deref(), Some("ProveIR { ... }"));
}

#[test]
fn edge_values_from_witness() {
    let prog = simple_program();
    let mut witness = HashMap::new();
    witness.insert(SsaVar(0), FieldElement::from_u64(6));
    witness.insert(SsaVar(1), FieldElement::from_u64(7));

    let graph = build_inspector_graph(
        &prog,
        &witness,
        &HashMap::new(),
        &HashMap::new(),
        None,
        None,
        None,
    );

    // Edge from node 0 (x=6) to node 2 (Mul) should have value "6"
    let edge_x_to_mul = graph
        .edges
        .iter()
        .find(|e| e.from_node == 0 && e.to_node == 2)
        .unwrap();
    assert_eq!(edge_x_to_mul.value.as_deref(), Some("6"));
    assert_eq!(edge_x_to_mul.wire_id, 0);
}
