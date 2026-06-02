//! Inspector graph builder — transforms IR + witness data into a DAG for visualization.
//!
//! Produces an `InspectorGraph` from an `IrProgram`, optional witness values,
//! and optional failure information. The graph is a JSON-serializable structure
//! suitable for rendering in the circuit inspector frontend.
//!
//! The graph is built from def-use chains: each IR instruction is a node,
//! and edges connect producer instructions to consumer instructions via SsaVar.

mod builder;
mod labels;
mod model;

#[cfg(test)]
mod tests;

pub use builder::build_inspector_graph;
pub use model::{
    InspectorEdge, InspectorGraph, InspectorMetadata, InspectorNode, NodeKind, NodeStatus,
};
