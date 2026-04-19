//! Inspector graph builder — transforms IR + witness data into a DAG for visualization.
//!
//! Produces an `InspectorGraph` from an `IrProgram`, optional witness values,
//! and optional failure information. The graph is a JSON-serializable structure
//! suitable for rendering in the circuit inspector frontend.
//!
//! The graph is built from def-use chains: each IR instruction is a node,
//! and edges connect producer instructions to consumer instructions via SsaVar.

use std::collections::{HashMap, HashSet, VecDeque};

use memory::{FieldBackend, FieldElement};
use serde::Serialize;

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

// ---------------------------------------------------------------------------
// Graph data structures
// ---------------------------------------------------------------------------

/// The complete inspector graph, ready for JSON serialization.
#[derive(Debug, Clone, Serialize)]
pub struct InspectorGraph {
    pub nodes: Vec<InspectorNode>,
    pub edges: Vec<InspectorEdge>,
    pub metadata: InspectorMetadata,
    /// Source code of the .ach file (for the source panel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_code: Option<String>,
    /// ProveIR textual representation (for the ProveIR panel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_ir_text: Option<String>,
}

/// A node in the inspector DAG — one per IR instruction.
#[derive(Debug, Clone, Serialize)]
pub struct InspectorNode {
    /// Node index (= instruction index in the IR program).
    pub id: usize,
    /// The kind of operation.
    pub kind: NodeKind,
    /// Human-readable label (e.g., "PoseidonHash", "Mul", "Input(x)").
    pub label: String,
    /// The SSA variable defined by this instruction.
    pub result_var: u32,
    /// Evaluated value as a display string, if witness is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Source line number (1-indexed), if span is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<usize>,
    /// Source column number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_col: Option<usize>,
    /// Source file path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Number of R1CS constraints this instruction generates.
    pub constraint_count: usize,
    /// Node status: ok, failed, or on the failure path.
    pub status: NodeStatus,
    /// Source-level variable name, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User-provided assert message (for AssertEq/Assert nodes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// An edge connecting a producer node to a consumer node via an SSA wire.
#[derive(Debug, Clone, Serialize)]
pub struct InspectorEdge {
    /// Index of the producer node (defines the wire).
    pub from_node: usize,
    /// Index of the consumer node (uses the wire).
    pub to_node: usize,
    /// The SSA variable (wire) connecting them.
    pub wire_id: u32,
    /// Wire value as a display string, if witness is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Circuit-level metadata for the inspector header.
#[derive(Debug, Clone, Serialize)]
pub struct InspectorMetadata {
    pub name: String,
    pub n_public: usize,
    pub n_witness: usize,
    pub n_instructions: usize,
    pub total_constraints: usize,
}

/// The kind of IR operation a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Const,
    Input,
    Add,
    Sub,
    Mul,
    Div,
    Neg,
    Mux,
    AssertEq,
    Assert,
    PoseidonHash,
    RangeCheck,
    Not,
    And,
    Or,
    IsEq,
    IsNeq,
    IsLt,
    IsLe,
    IsLtBounded,
    IsLeBounded,
    WitnessCall,
}

/// Status of a node in the inspector visualization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeStatus {
    /// Constraint satisfied (or non-constraining node).
    Ok,
    /// This node's constraint failed.
    Failed {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// On the path from a failed node back to inputs.
    OnFailurePath {
        /// BFS distance from the nearest failed node.
        distance: usize,
    },
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an IR instruction to its NodeKind.
fn node_kind<F: FieldBackend>(inst: &Instruction<F>) -> NodeKind {
    match inst {
        Instruction::Const { .. } => NodeKind::Const,
        Instruction::Input { .. } => NodeKind::Input,
        Instruction::Add { .. } => NodeKind::Add,
        Instruction::Sub { .. } => NodeKind::Sub,
        Instruction::Mul { .. } => NodeKind::Mul,
        Instruction::Div { .. } => NodeKind::Div,
        Instruction::Neg { .. } => NodeKind::Neg,
        Instruction::Mux { .. } => NodeKind::Mux,
        Instruction::AssertEq { .. } => NodeKind::AssertEq,
        Instruction::Assert { .. } => NodeKind::Assert,
        Instruction::PoseidonHash { .. } => NodeKind::PoseidonHash,
        Instruction::RangeCheck { .. } => NodeKind::RangeCheck,
        Instruction::Not { .. } => NodeKind::Not,
        Instruction::And { .. } => NodeKind::And,
        Instruction::Or { .. } => NodeKind::Or,
        Instruction::IsEq { .. } => NodeKind::IsEq,
        Instruction::IsNeq { .. } => NodeKind::IsNeq,
        Instruction::IsLt { .. } => NodeKind::IsLt,
        Instruction::IsLe { .. } => NodeKind::IsLe,
        Instruction::IsLtBounded { .. } => NodeKind::IsLtBounded,
        Instruction::IsLeBounded { .. } => NodeKind::IsLeBounded,
        Instruction::Decompose { .. } => NodeKind::RangeCheck,
        Instruction::IntDiv { .. } => NodeKind::Div,
        Instruction::IntMod { .. } => NodeKind::Div,
        Instruction::WitnessCall { .. } => NodeKind::WitnessCall,
    }
}

/// Produce a human-readable label for a node.
fn node_label<F: FieldBackend>(inst: &Instruction<F>, program: &IrProgram<F>) -> String {
    match inst {
        Instruction::Const { value, .. } => {
            let s = format_field(value);
            format!("Const({s})")
        }
        Instruction::Input {
            name, visibility, ..
        } => {
            let vis = match visibility {
                Visibility::Public => "public",
                Visibility::Witness => "witness",
            };
            format!("Input({name}, {vis})")
        }
        Instruction::Add { result, .. } => label_with_name("Add", *result, program),
        Instruction::Sub { result, .. } => label_with_name("Sub", *result, program),
        Instruction::Mul { result, .. } => label_with_name("Mul", *result, program),
        Instruction::Div { result, .. } => label_with_name("Div", *result, program),
        Instruction::Neg { result, .. } => label_with_name("Neg", *result, program),
        Instruction::Mux { result, .. } => label_with_name("Mux", *result, program),
        Instruction::AssertEq { message, .. } => match message {
            Some(msg) => format!("AssertEq(\"{msg}\")"),
            None => "AssertEq".to_string(),
        },
        Instruction::Assert { message, .. } => match message {
            Some(msg) => format!("Assert(\"{msg}\")"),
            None => "Assert".to_string(),
        },
        Instruction::PoseidonHash { result, .. } => {
            label_with_name("PoseidonHash", *result, program)
        }
        Instruction::RangeCheck { bits, .. } => format!("RangeCheck({bits})"),
        Instruction::Not { .. } => "Not".to_string(),
        Instruction::And { .. } => "And".to_string(),
        Instruction::Or { .. } => "Or".to_string(),
        Instruction::IsEq { .. } => "IsEq".to_string(),
        Instruction::IsNeq { .. } => "IsNeq".to_string(),
        Instruction::IsLt { .. } => "IsLt".to_string(),
        Instruction::IsLe { .. } => "IsLe".to_string(),
        Instruction::IsLtBounded { bitwidth, .. } => format!("IsLtBounded({bitwidth})"),
        Instruction::IsLeBounded { bitwidth, .. } => format!("IsLeBounded({bitwidth})"),
        Instruction::Decompose {
            num_bits, result, ..
        } => {
            let base = format!("Decompose({num_bits})");
            match program.get_name(*result) {
                Some(name) => format!("{base} ({name})"),
                None => base,
            }
        }
        Instruction::IntDiv { result, .. } => label_with_name("IntDiv", *result, program),
        Instruction::IntMod { result, .. } => label_with_name("IntMod", *result, program),
        Instruction::WitnessCall {
            outputs,
            program_bytes,
            ..
        } => {
            let primary = outputs.first().copied().unwrap_or(SsaVar(0));
            let bytes = program_bytes.len();
            let base = format!("WitnessCall[{}x]({} bytes)", outputs.len(), bytes);
            match program.get_name(primary) {
                Some(name) => format!("{base} ({name})"),
                None => base,
            }
        }
    }
}

/// Append variable name if available: "Mul" → "Mul (product)".
fn label_with_name<F: FieldBackend>(base: &str, var: SsaVar, program: &IrProgram<F>) -> String {
    match program.get_name(var) {
        Some(name) => format!("{base} ({name})"),
        None => base.to_string(),
    }
}

/// Format a field element for display.
/// Small values (< 2^64) show as decimal; large values as truncated hex.
fn format_field<F: FieldBackend>(fe: &FieldElement<F>) -> String {
    let limbs = fe.to_canonical();
    // If upper 3 limbs are zero, it fits in u64 — show decimal
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        return limbs[0].to_string();
    }
    // Otherwise show as hex, truncated for readability
    let hex = format!(
        "{:016x}{:016x}{:016x}{:016x}",
        limbs[3], limbs[2], limbs[1], limbs[0]
    );
    let trimmed = hex.trim_start_matches('0');
    if trimmed.len() <= 16 {
        format!("0x{trimmed}")
    } else {
        format!("0x{}…{}", &trimmed[..8], &trimmed[trimmed.len() - 4..])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Instruction, IrProgram, SsaVar, Visibility};
    use memory::{Bn254Fr, FieldElement};

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
}
