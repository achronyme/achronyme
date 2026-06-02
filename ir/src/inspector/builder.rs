use std::collections::{HashMap, HashSet, VecDeque};

use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

use super::labels::{format_field, node_kind, node_label};
use super::model::{InspectorEdge, InspectorGraph, InspectorMetadata, InspectorNode, NodeStatus};

/// Build an inspector graph from IR program data.
///
/// # Arguments
/// * `program` — The optimized IR program.
/// * `witness_values` — Per-SsaVar evaluated values (from IR evaluation or witness generation).
/// * `failed_nodes` — IR instruction indices that had constraint failures, with optional messages.
/// * `constraint_counts` — Per-instruction constraint count (from `constraint_origins`).
/// * `source_code` — The original .ach source (for the source panel).
/// * `prove_ir_text` — ProveIR Display text (for the ProveIR panel).
/// * `circuit_name` — Circuit name from ProveIR metadata.
pub fn build_inspector_graph<F: FieldBackend>(
    program: &IrProgram<F>,
    witness_values: &HashMap<SsaVar, FieldElement<F>>,
    failed_nodes: &HashMap<usize, Option<String>>,
    constraint_counts: &HashMap<usize, usize>,
    source_code: Option<String>,
    prove_ir_text: Option<String>,
    circuit_name: Option<&str>,
) -> InspectorGraph {
    let instructions = &program.instructions;

    // 1. Build def map: SsaVar → instruction index (for edge construction)
    let mut def_map: HashMap<SsaVar, usize> = HashMap::new();
    for (idx, inst) in instructions.iter().enumerate() {
        def_map.insert(inst.result_var(), idx);
    }

    // 2. Build nodes
    let mut nodes: Vec<InspectorNode> = Vec::with_capacity(instructions.len());
    let mut n_public = 0usize;
    let mut n_witness = 0usize;

    for (idx, inst) in instructions.iter().enumerate() {
        let result_var = inst.result_var();
        let kind = node_kind(inst);
        let label = node_label(inst, program);

        // Witness value
        let value = witness_values.get(&result_var).map(format_field);

        // Source span
        let span = program.get_span(result_var);
        let source_line = span.map(|s| s.line_start);
        let source_col = span.map(|s| s.col_start);
        let source_file = span
            .and_then(|s| s.file.as_ref())
            .map(|p| p.display().to_string());

        // Constraint count
        let constraint_count = constraint_counts.get(&idx).copied().unwrap_or(0);

        // Status
        let status = if let Some(msg) = failed_nodes.get(&idx) {
            NodeStatus::Failed {
                message: msg.clone(),
            }
        } else {
            NodeStatus::Ok
        };

        // Name and message
        let name = program.get_name(result_var).map(|s| s.to_string());
        let message = match inst {
            Instruction::AssertEq { message, .. } | Instruction::Assert { message, .. } => {
                message.clone()
            }
            _ => None,
        };

        // Count inputs
        if let Instruction::Input { visibility, .. } = inst {
            match visibility {
                Visibility::Public => n_public += 1,
                Visibility::Witness => n_witness += 1,
            }
        }

        nodes.push(InspectorNode {
            id: idx,
            kind,
            label,
            result_var: result_var.0,
            value,
            source_line,
            source_col,
            source_file,
            constraint_count,
            status,
            name,
            message,
        });
    }

    // 3. Build edges from def-use chains
    let mut edges: Vec<InspectorEdge> = Vec::new();
    for (idx, inst) in instructions.iter().enumerate() {
        for operand in inst.operands() {
            if let Some(&from_idx) = def_map.get(&operand) {
                let value = witness_values.get(&operand).map(format_field);
                edges.push(InspectorEdge {
                    from_node: from_idx,
                    to_node: idx,
                    wire_id: operand.0,
                    value,
                });
            }
        }
    }

    // 4. Failure path tracing: BFS backward from failed nodes
    if !failed_nodes.is_empty() {
        // Build reverse adjacency: node → list of nodes that use its output
        // We need forward adjacency: node → list of nodes whose output it uses
        // Actually we need backward: from a failed node, walk UP to inputs.
        // "Backward" = follow operands: failed_node uses operand → go to operand's def.
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new(); // (node_idx, distance)
        let mut visited: HashSet<usize> = HashSet::new();

        // Seed with failed nodes
        for &failed_idx in failed_nodes.keys() {
            queue.push_back((failed_idx, 0));
            visited.insert(failed_idx);
        }

        // BFS backward through operand chains
        while let Some((node_idx, dist)) = queue.pop_front() {
            if node_idx >= instructions.len() {
                continue;
            }
            for operand in instructions[node_idx].operands() {
                if let Some(&def_idx) = def_map.get(&operand) {
                    if visited.insert(def_idx) {
                        let new_dist = dist + 1;
                        // Only mark as OnFailurePath if not already Failed
                        if !failed_nodes.contains_key(&def_idx) {
                            nodes[def_idx].status =
                                NodeStatus::OnFailurePath { distance: new_dist };
                        }
                        queue.push_back((def_idx, new_dist));
                    }
                }
            }
        }
    }

    // 5. Compute total constraints
    let total_constraints: usize = constraint_counts.values().sum();

    let metadata = InspectorMetadata {
        name: circuit_name.unwrap_or("<anonymous>").to_string(),
        n_public,
        n_witness,
        n_instructions: instructions.len(),
        total_constraints,
    };

    InspectorGraph {
        nodes,
        edges,
        metadata,
        source_code,
        prove_ir_text,
    }
}
