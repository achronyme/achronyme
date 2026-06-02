use serde::Serialize;

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
    pub result_var: u64,
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
    pub wire_id: u64,
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
