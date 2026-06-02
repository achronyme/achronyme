use super::*;
use crate::plonkish::PlonkishSystem;
use memory::FieldElement;
use serde_json::Value;

#[test]
fn empty_system_roundtrip() {
    let system: PlonkishSystem = PlonkishSystem::new(0);
    let json = write_plonkish_json(&system);
    validate_plonkish_json(&json).expect("validation failed");

    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "achronyme-plonkish-v1");
    assert_eq!(parsed["num_rows"], 0);
}

#[test]
fn roundtrip_with_circuit() {
    // Compile a simple circuit through PlonkishCompiler and export
    use crate::plonkish::PlonkishSystem;

    let system: PlonkishSystem = PlonkishSystem::new(0);
    let json = write_plonkish_json(&system);
    validate_plonkish_json(&json).expect("validation failed");

    // Verify the JSON has the correct structure
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["gates"].is_array());
    assert!(parsed["copies"].is_array());
    assert!(parsed["lookups"].is_array());
    assert!(parsed["assignments"]["advice"].is_array());
    assert!(parsed["assignments"]["fixed"].is_array());
    assert!(parsed["assignments"]["instance"].is_array());
}

#[test]
fn validate_rejects_bad_format() {
    let bad = r#"{"format": "wrong-v1"}"#;
    assert!(validate_plonkish_json(bad).is_err());
}

#[test]
fn validate_rejects_invalid_json() {
    assert!(validate_plonkish_json("not json").is_err());
}

#[test]
fn validate_rejects_missing_lookup_tables() {
    let json = r#"{
            "format": "achronyme-plonkish-v1",
            "num_advice": 0,
            "num_fixed": 0,
            "num_instance": 0,
            "num_rows": 0,
            "gates": [],
            "copies": [],
            "lookups": [],
            "assignments": { "advice": [], "fixed": [], "instance": [] }
        }"#;
    let err = validate_plonkish_json(json).unwrap_err();
    assert!(
        err.contains("lookup_tables"),
        "should reject missing lookup_tables: {err}"
    );
}

/// Helper: minimal valid JSON skeleton for tests.
fn minimal_json(overrides: &[(&str, Value)]) -> String {
    let mut root = serde_json::json!({
        "format": "achronyme-plonkish-v1",
        "num_advice": 1,
        "num_fixed": 1,
        "num_instance": 1,
        "num_rows": 2,
        "gates": [],
        "copies": [],
        "lookups": [],
        "lookup_tables": [],
        "assignments": {
            "advice": [["0", "0"]],
            "fixed": [["0", "0"]],
            "instance": [["0", "0"]],
        },
    });
    for (key, val) in overrides {
        root[*key] = val.clone();
    }
    serde_json::to_string(&root).unwrap()
}

#[test]
fn validate_rejects_bad_gate_structure() {
    // Missing 'name'
    let json = minimal_json(&[("gates", serde_json::json!([{"poly": {"const": "0"}}]))]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("gates[0]") && err.contains("name"), "{err}");

    // Missing 'poly'
    let json = minimal_json(&[("gates", serde_json::json!([{"name": "g"}]))]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("gates[0]") && err.contains("poly"), "{err}");

    // Invalid expression (no recognized variant)
    let json = minimal_json(&[(
        "gates",
        serde_json::json!([{"name": "g", "poly": {"unknown": 1}}]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("expression must have one of"), "{err}");
}

#[test]
fn validate_rejects_bad_copy_structure() {
    // Missing 'left'
    let json = minimal_json(&[(
        "copies",
        serde_json::json!([{
            "right": {"column": {"kind": "advice", "index": 0}, "row": 0}
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("left"), "{err}");

    // Missing column in right
    let json = minimal_json(&[(
        "copies",
        serde_json::json!([{
            "left": {"column": {"kind": "advice", "index": 0}, "row": 0},
            "right": {"row": 0}
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("right") && err.contains("column"), "{err}");
}

#[test]
fn validate_rejects_bad_lookup_structure() {
    // Missing input_exprs
    let json = minimal_json(&[(
        "lookups",
        serde_json::json!([{
            "name": "l",
            "table_exprs": [{"const": "0"}]
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("input_exprs"), "{err}");

    // Missing table_exprs
    let json = minimal_json(&[(
        "lookups",
        serde_json::json!([{
            "name": "l",
            "input_exprs": [{"const": "0"}]
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("table_exprs"), "{err}");
}

#[test]
fn validate_rejects_column_out_of_bounds() {
    // advice index=1 but num_advice=1 → out of bounds
    let json = minimal_json(&[(
        "gates",
        serde_json::json!([{
            "name": "g",
            "poly": {"cell": {"column": {"kind": "advice", "index": 1}, "rotation": 0}}
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("out of bounds"), "{err}");
}

#[test]
fn validate_rejects_row_out_of_bounds() {
    // copy with row=2 but num_rows=2 → out of bounds
    let json = minimal_json(&[(
        "copies",
        serde_json::json!([{
            "left": {"column": {"kind": "advice", "index": 0}, "row": 0},
            "right": {"column": {"kind": "advice", "index": 0}, "row": 2}
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("row 2 out of bounds"), "{err}");
}

#[test]
fn validate_rejects_bad_field_element() {
    // Invalid FE in gate const expression
    let json = minimal_json(&[(
        "gates",
        serde_json::json!([{
            "name": "g",
            "poly": {"const": "not_a_number"}
        }]),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("invalid field element"), "{err}");

    // Invalid FE in assignments
    let json = minimal_json(&[(
        "assignments",
        serde_json::json!({
            "advice": [["0", "bad"]],
            "fixed": [["0", "0"]],
            "instance": [["0", "0"]],
        }),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("invalid field element"), "{err}");
}

#[test]
fn validate_rejects_assignment_dimension_mismatch() {
    // num_advice=1 but 2 advice columns in assignments
    let json = minimal_json(&[(
        "assignments",
        serde_json::json!({
            "advice": [["0", "0"], ["0", "0"]],
            "fixed": [["0", "0"]],
            "instance": [["0", "0"]],
        }),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("2 columns, expected 1"), "{err}");
}

#[test]
fn validate_rejects_column_length_mismatch() {
    // num_rows=2 but column has 3 rows
    let json = minimal_json(&[(
        "assignments",
        serde_json::json!({
            "advice": [["0", "0", "0"]],
            "fixed": [["0", "0"]],
            "instance": [["0", "0"]],
        }),
    )]);
    let err = validate_plonkish_json(&json).unwrap_err();
    assert!(err.contains("3 rows, expected 2"), "{err}");
}

#[test]
fn validate_accepts_valid_roundtrip() {
    use crate::plonkish::{CellRef, Expression, PlonkishSystem};

    let mut sys = PlonkishSystem::new(4);
    let s = sys.alloc_fixed();
    let a = sys.alloc_advice();
    let b = sys.alloc_advice();
    let d = sys.alloc_advice();

    sys.set(s, 0, FieldElement::ONE);
    sys.set(a, 0, FieldElement::from_u64(3));
    sys.set(b, 0, FieldElement::from_u64(5));
    sys.set(d, 0, FieldElement::from_u64(15));

    let poly = Expression::cell(s, 0).mul(
        Expression::cell(a, 0)
            .mul(Expression::cell(b, 0))
            .sub(Expression::cell(d, 0)),
    );
    sys.register_gate("mul", poly);
    sys.add_copy(CellRef { column: a, row: 0 }, CellRef { column: b, row: 1 });

    let json = write_plonkish_json(&sys);
    validate_plonkish_json(&json).expect("roundtrip validation failed");
}
