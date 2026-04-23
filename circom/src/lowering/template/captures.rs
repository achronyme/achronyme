//! Capture analysis: classify template parameters by how they appear
//! in the lowered body.
//!
//! After [`super::lower::lower_template_with_captures`] produces the
//! `Vec<CircuitNode>` body, we walk it once to figure out which
//! template parameters are referenced from structural positions
//! (loop bounds, `Pow` exponents — they shape the circuit) versus
//! circuit positions (constraint expressions — they feed values into
//! the circuit). The result is a `Vec<CaptureDef>` consumed by the
//! ProveIR instantiator.

use std::collections::HashSet;

use ir_forge::types::{CaptureDef, CaptureUsage, CircuitExpr, CircuitNode, ForRange};

/// Classify template parameter captures based on how they are used in the body.
///
/// - **StructureOnly**: only in loop bounds (`ForRange::WithCapture`) or
///   `Pow` exponents — affects circuit shape, not constraint values.
/// - **CircuitInput**: only in constraint expressions (`CircuitExpr::Capture`).
/// - **Both**: used in both structural and constraint positions.
pub(super) fn classify_captures(params: &[String], body: &[CircuitNode]) -> Vec<CaptureDef> {
    let mut structural: HashSet<&str> = HashSet::new();
    let mut circuit: HashSet<&str> = HashSet::new();

    for node in body {
        collect_capture_usage(node, &mut structural, &mut circuit);
    }

    let param_set: HashSet<&str> = params.iter().map(|s| s.as_str()).collect();
    let mut captures = Vec::new();

    for param in params {
        if !param_set.contains(param.as_str()) {
            continue;
        }
        let in_struct = structural.contains(param.as_str());
        let in_circuit = circuit.contains(param.as_str());

        if !in_struct && !in_circuit {
            // Capture is declared but never referenced — still include it
            // as StructureOnly (no-op at instantiation).
            captures.push(CaptureDef {
                name: param.clone(),
                usage: CaptureUsage::StructureOnly,
            });
        } else {
            let usage = match (in_struct, in_circuit) {
                (true, true) => CaptureUsage::Both,
                (true, false) => CaptureUsage::StructureOnly,
                (false, true) => CaptureUsage::CircuitInput,
                (false, false) => unreachable!(
                    "capture appears in scan but is used in neither structure nor circuit"
                ),
            };
            captures.push(CaptureDef {
                name: param.clone(),
                usage,
            });
        }
    }

    captures
}

/// Walk a CircuitNode, recording which captures appear in structural vs
/// circuit positions.
fn collect_capture_usage<'a>(
    node: &'a CircuitNode,
    structural: &mut HashSet<&'a str>,
    circuit: &mut HashSet<&'a str>,
) {
    match node {
        CircuitNode::Let { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::LetArray { elements, .. } => {
            for e in elements {
                collect_expr_captures(e, circuit);
            }
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            collect_expr_captures(lhs, circuit);
            collect_expr_captures(rhs, circuit);
        }
        CircuitNode::Assert { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::For { range, body, .. } => {
            // Loop bound captures are structural
            match range {
                ForRange::WithCapture { end_capture, .. } => {
                    structural.insert(end_capture.as_str());
                }
                ForRange::WithExpr { end_expr, .. } => {
                    // Captures in loop bound expressions are structural
                    collect_expr_captures(end_expr, structural);
                }
                ForRange::Literal { .. } | ForRange::Array(_) => {}
            }
            for n in body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            collect_expr_captures(cond, circuit);
            for n in then_body {
                collect_capture_usage(n, structural, circuit);
            }
            for n in else_body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::Expr { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::Decompose { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::WitnessHint { hint, .. } => collect_expr_captures(hint, circuit),
        CircuitNode::LetIndexed { index, value, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(value, circuit);
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(hint, circuit);
        }
        CircuitNode::WitnessCall { input_signals, .. } => {
            // The Artik bytecode is opaque; only the caller-built
            // input-signal expressions can reference captures.
            for sig in input_signals {
                collect_expr_captures(sig, circuit);
            }
        }
    }
}

/// Collect all `Capture(name)` references in a circuit expression.
fn collect_expr_captures<'a>(expr: &'a CircuitExpr, captures: &mut HashSet<&'a str>) {
    match expr {
        CircuitExpr::Capture(name) => {
            captures.insert(name.as_str());
        }
        CircuitExpr::BinOp { lhs, rhs, .. }
        | CircuitExpr::Comparison { lhs, rhs, .. }
        | CircuitExpr::BoolOp { lhs, rhs, .. }
        | CircuitExpr::IntDiv { lhs, rhs, .. }
        | CircuitExpr::IntMod { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::UnaryOp { operand, .. } => collect_expr_captures(operand, captures),
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            collect_expr_captures(cond, captures);
            collect_expr_captures(if_true, captures);
            collect_expr_captures(if_false, captures);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            collect_expr_captures(left, captures);
            collect_expr_captures(right, captures);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args {
                collect_expr_captures(a, captures);
            }
        }
        CircuitExpr::RangeCheck { value, .. } => collect_expr_captures(value, captures),
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            collect_expr_captures(root, captures);
            collect_expr_captures(leaf, captures);
        }
        CircuitExpr::ArrayIndex { index, .. } => collect_expr_captures(index, captures),
        CircuitExpr::Pow { base, .. } => collect_expr_captures(base, captures),
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::BitNot { operand, .. } => {
            collect_expr_captures(operand, captures);
        }
        CircuitExpr::ShiftR { operand, shift, .. } | CircuitExpr::ShiftL { operand, shift, .. } => {
            collect_expr_captures(operand, captures);
            collect_expr_captures(shift, captures);
        }
        // Leaf nodes with no captures
        CircuitExpr::Const(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}
    }
}
