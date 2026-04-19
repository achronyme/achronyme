//! Capture detection and classification for ProveIR.
//!
//! Walks the compiled ProveIR body to determine how each captured variable
//! is used: structurally (loop bounds, array sizes, exponents), in constraint
//! expressions, or both.

use std::collections::HashSet;

use super::types::*;

/// Classify all captured variables in a ProveIR body.
///
/// `captured_names`: the set of names detected as captures during compilation.
/// Returns a `Vec<CaptureDef>` with usage classification for each.
pub fn classify_captures(
    captured_names: &HashSet<String>,
    body: &[CircuitNode],
) -> Vec<CaptureDef> {
    if captured_names.is_empty() {
        return Vec::new();
    }

    let mut structural_uses: HashSet<String> = HashSet::new();
    let mut constraint_uses: HashSet<String> = HashSet::new();

    walk_nodes(body, &mut structural_uses, &mut constraint_uses);

    let mut result: Vec<CaptureDef> = captured_names
        .iter()
        .map(|name| {
            let is_structural = structural_uses.contains(name);
            let is_constraint = constraint_uses.contains(name);
            let usage = match (is_structural, is_constraint) {
                (true, true) => CaptureUsage::Both,
                (true, false) => CaptureUsage::StructureOnly,
                (false, true) => CaptureUsage::CircuitInput,
                // Referenced but not in any classifiable position — treat as circuit input
                (false, false) => CaptureUsage::CircuitInput,
            };
            CaptureDef {
                name: name.clone(),
                usage,
            }
        })
        .collect();

    // Sort for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

// ---------------------------------------------------------------------------
// Tree walkers
// ---------------------------------------------------------------------------

fn walk_nodes(
    nodes: &[CircuitNode],
    structural: &mut HashSet<String>,
    constraint: &mut HashSet<String>,
) {
    for node in nodes {
        walk_node(node, structural, constraint);
    }
}

fn walk_node(
    node: &CircuitNode,
    structural: &mut HashSet<String>,
    constraint: &mut HashSet<String>,
) {
    match node {
        CircuitNode::Let { value, .. } => {
            walk_expr(value, false, structural, constraint);
        }
        CircuitNode::LetArray { elements, .. } => {
            for elem in elements {
                walk_expr(elem, false, structural, constraint);
            }
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            walk_expr(lhs, false, structural, constraint);
            walk_expr(rhs, false, structural, constraint);
        }
        CircuitNode::Assert { expr, .. } => {
            walk_expr(expr, false, structural, constraint);
        }
        CircuitNode::For { range, body, .. } => {
            // The range is a structural position
            match range {
                ForRange::Literal { .. } => {}
                ForRange::WithCapture { end_capture, .. } => {
                    structural.insert(end_capture.clone());
                }
                ForRange::WithExpr { end_expr, .. } => {
                    // All captures in a loop bound expression are structural
                    walk_expr(end_expr, true, structural, constraint);
                }
                ForRange::Array(name) => {
                    // Iterating over an array is structural (determines loop count)
                    structural.insert(name.clone());
                }
            }
            walk_nodes(body, structural, constraint);
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            walk_expr(cond, false, structural, constraint);
            walk_nodes(then_body, structural, constraint);
            walk_nodes(else_body, structural, constraint);
        }
        CircuitNode::Expr { expr, .. } => {
            walk_expr(expr, false, structural, constraint);
        }
        CircuitNode::Decompose { value, .. } => {
            walk_expr(value, false, structural, constraint);
        }
        CircuitNode::WitnessHint { hint, .. } => {
            // Hint expression is evaluated off-circuit, but captures
            // referenced in it still need to be provided as values.
            walk_expr(hint, false, structural, constraint);
        }
        CircuitNode::LetIndexed { index, value, .. } => {
            walk_expr(index, false, structural, constraint);
            walk_expr(value, false, structural, constraint);
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            walk_expr(index, false, structural, constraint);
            walk_expr(hint, false, structural, constraint);
        }
        CircuitNode::WitnessCall { input_signals, .. } => {
            // Artik programs are opaque bytecode; their captures are
            // reached purely through the argument expressions the
            // caller built at lowering time.
            for sig in input_signals {
                walk_expr(sig, false, structural, constraint);
            }
        }
    }
}

/// Walk an expression, tracking captures.
/// `in_structural`: true when inside a structural position (loop bound, exponent, etc.)
fn walk_expr(
    expr: &CircuitExpr,
    in_structural: bool,
    structural: &mut HashSet<String>,
    constraint: &mut HashSet<String>,
) {
    match expr {
        CircuitExpr::Capture(name) => {
            if in_structural {
                structural.insert(name.clone());
            } else {
                constraint.insert(name.clone());
            }
        }

        // Leaf nodes — no captures to track
        CircuitExpr::Const(_) | CircuitExpr::Input(_) | CircuitExpr::Var(_) => {}

        // Recursive cases — constraint context
        CircuitExpr::BinOp { lhs, rhs, .. } => {
            walk_expr(lhs, in_structural, structural, constraint);
            walk_expr(rhs, in_structural, structural, constraint);
        }
        CircuitExpr::UnaryOp { operand, .. } => {
            walk_expr(operand, in_structural, structural, constraint);
        }
        CircuitExpr::Comparison { lhs, rhs, .. } => {
            walk_expr(lhs, in_structural, structural, constraint);
            walk_expr(rhs, in_structural, structural, constraint);
        }
        CircuitExpr::BoolOp { lhs, rhs, .. } => {
            walk_expr(lhs, in_structural, structural, constraint);
            walk_expr(rhs, in_structural, structural, constraint);
        }
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            walk_expr(cond, in_structural, structural, constraint);
            walk_expr(if_true, in_structural, structural, constraint);
            walk_expr(if_false, in_structural, structural, constraint);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            walk_expr(left, in_structural, structural, constraint);
            walk_expr(right, in_structural, structural, constraint);
        }
        CircuitExpr::PoseidonMany(args) => {
            for arg in args {
                walk_expr(arg, in_structural, structural, constraint);
            }
        }
        CircuitExpr::RangeCheck { value, .. } => {
            // The value is in constraint context, bits is a literal u32
            walk_expr(value, in_structural, structural, constraint);
        }
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            walk_expr(root, in_structural, structural, constraint);
            walk_expr(leaf, in_structural, structural, constraint);
        }

        // Structural positions — captures here affect circuit structure
        CircuitExpr::Pow { base, .. } => {
            // base is in constraint context, exp is a u64 literal (already resolved)
            walk_expr(base, in_structural, structural, constraint);
        }
        CircuitExpr::ArrayIndex { index, .. } => {
            // The index is classified as structural because it determines which
            // wire to select. This is correct only if Phase B resolves it to a
            // compile-time constant (selecting a specific element). If the index
            // remains dynamic, Phase B must generate a MUX tree over all possible
            // elements, and the index itself becomes a constraint wire — but the
            // capture classification still holds because a structural capture is
            // resolved before circuit construction, making the MUX generation
            // deterministic.
            walk_expr(index, true, structural, constraint);
        }
        CircuitExpr::ArrayLen(_) => {
            // ArrayLen references an array name — structural by nature
            // (but the name is already known at compile time for literal arrays)
        }
        CircuitExpr::IntDiv { lhs, rhs, .. } | CircuitExpr::IntMod { lhs, rhs, .. } => {
            walk_expr(lhs, in_structural, structural, constraint);
            walk_expr(rhs, in_structural, structural, constraint);
        }
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            walk_expr(lhs, in_structural, structural, constraint);
            walk_expr(rhs, in_structural, structural, constraint);
        }
        CircuitExpr::BitNot { operand, .. }
        | CircuitExpr::ShiftR { operand, .. }
        | CircuitExpr::ShiftL { operand, .. } => {
            walk_expr(operand, in_structural, structural, constraint);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn find_capture<'a>(captures: &'a [CaptureDef], name: &str) -> Option<&'a CaptureDef> {
        captures.iter().find(|c| c.name == name)
    }

    #[test]
    fn empty_captures() {
        let result = classify_captures(&HashSet::new(), &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn capture_in_constraint_expr() {
        // secret used in assert_eq → CircuitInput
        let body = vec![CircuitNode::AssertEq {
            lhs: CircuitExpr::Capture("secret".into()),
            rhs: CircuitExpr::Const(FieldConst::from_u64(0)),
            message: None,
            span: None,
        }];
        let result = classify_captures(&names(&["secret"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::CircuitInput);
    }

    #[test]
    fn capture_in_for_range() {
        // n used as loop bound → StructureOnly
        let body = vec![CircuitNode::For {
            var: "i".into(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "n".into(),
            },
            body: vec![],
            span: None,
        }];
        let result = classify_captures(&names(&["n"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::StructureOnly);
    }

    #[test]
    fn capture_in_array_iteration() {
        // arr used as for iterable → StructureOnly
        let body = vec![CircuitNode::For {
            var: "x".into(),
            range: ForRange::Array("arr".into()),
            body: vec![],
            span: None,
        }];
        let result = classify_captures(&names(&["arr"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::StructureOnly);
    }

    #[test]
    fn capture_in_both_positions() {
        // n used as loop bound AND in arithmetic → Both
        let body = vec![
            CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![],
                span: None,
            },
            CircuitNode::Let {
                name: "x".into(),
                value: CircuitExpr::BinOp {
                    op: CircuitBinOp::Mul,
                    lhs: Box::new(CircuitExpr::Capture("n".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(2))),
                },
                span: None,
            },
        ];
        let result = classify_captures(&names(&["n"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::Both);
    }

    #[test]
    fn multiple_captures_classified() {
        let body = vec![
            // secret in constraint
            CircuitNode::AssertEq {
                lhs: CircuitExpr::Capture("secret".into()),
                rhs: CircuitExpr::Input("hash".into()),
                message: None,
                span: None,
            },
            // n as loop bound
            CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![],
                span: None,
            },
        ];
        let result = classify_captures(&names(&["secret", "n"]), &body);
        assert_eq!(result.len(), 2);
        let secret = find_capture(&result, "secret").unwrap();
        let n = find_capture(&result, "n").unwrap();
        assert_eq!(secret.usage, CaptureUsage::CircuitInput);
        assert_eq!(n.usage, CaptureUsage::StructureOnly);
    }

    #[test]
    fn capture_in_array_index_is_structural() {
        // arr[i] where i is a capture → structural
        let body = vec![CircuitNode::Let {
            name: "x".into(),
            value: CircuitExpr::ArrayIndex {
                array: "arr".into(),
                index: Box::new(CircuitExpr::Capture("i".into())),
            },
            span: None,
        }];
        let result = classify_captures(&names(&["i"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::StructureOnly);
    }

    #[test]
    fn capture_in_nested_if() {
        // Capture inside if/else body → constraint
        let body = vec![CircuitNode::If {
            cond: CircuitExpr::Const(FieldConst::from_u64(1)),
            then_body: vec![CircuitNode::AssertEq {
                lhs: CircuitExpr::Capture("x".into()),
                rhs: CircuitExpr::Const(FieldConst::from_u64(0)),
                message: None,
                span: None,
            }],
            else_body: vec![],
            span: None,
        }];
        let result = classify_captures(&names(&["x"]), &body);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].usage, CaptureUsage::CircuitInput);
    }

    #[test]
    fn capture_sorted_alphabetically() {
        let body = vec![CircuitNode::AssertEq {
            lhs: CircuitExpr::Capture("z".into()),
            rhs: CircuitExpr::Capture("a".into()),
            message: None,
            span: None,
        }];
        let result = classify_captures(&names(&["z", "a"]), &body);
        assert_eq!(result[0].name, "a");
        assert_eq!(result[1].name, "z");
    }
}
