use super::*;
use ir_forge::types::{CaptureUsage, CircuitNode};

// ── Capture classification ─────────────────────────────────────

#[test]
fn capture_circuit_input() {
    let ir = parse_and_lower(
        r#"
        template Scale(factor) {
            signal input x;
            signal output y;
            y <== x * factor;
        }
        component main = Scale();
        "#,
    );

    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "factor");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}

#[test]
fn capture_unused_is_structure_only() {
    let ir = parse_and_lower(
        r#"
        template T(unused_param) {
            signal input x;
            signal output y;
            y <== x;
        }
        component main = T();
        "#,
    );

    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "unused_param");
    assert_eq!(ir.captures[0].usage, CaptureUsage::StructureOnly);
}

#[test]
fn capture_no_params_no_captures() {
    let ir = parse_and_lower(
        r#"
        template T() {
            signal input x;
            signal output y;
            y <== x;
        }
        component main = T();
        "#,
    );

    assert!(ir.captures.is_empty());
}

// ── Array literal expansion ────────────────────────────────────

#[test]
fn array_literal_expands_to_individual_lets() {
    let ir = parse_and_lower(
        r#"
        template T() {
            signal input x;
            signal output out;
            var coeffs = [1, 2, 3];
            out <== x * coeffs[1];
        }
        component main = T();
        "#,
    );

    // coeffs = [1, 2, 3] → Let(coeffs_0=1), Let(coeffs_1=2), Let(coeffs_2=3)
    // out <== x * coeffs[1] → Let(out) + AssertEq
    // coeffs[1] should resolve to Var("coeffs_1")
    let let_names: Vec<&str> = ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::Let { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(let_names.contains(&"coeffs_0"));
    assert!(let_names.contains(&"coeffs_1"));
    assert!(let_names.contains(&"coeffs_2"));
    assert!(let_names.contains(&"out"));
}
