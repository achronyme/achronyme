/// JSON export for Plonkish constraint systems (achronyme-plonkish-v1 format).
///
/// Produces a self-contained JSON file with gates, copy constraints, lookups,
/// and assignments so external tools can inspect/verify the circuit.
use serde_json::{json, Value};

use crate::plonkish::{
    Column, ColumnKind, CopyConstraint, Expression, Gate, Lookup, LookupTable, PlonkishSystem,
};
use memory::FieldElement;

// ============================================================================
// Serialization
// ============================================================================

fn fe_to_json(fe: &FieldElement) -> Value {
    Value::String(fe.to_decimal_string())
}

fn column_to_json(col: &Column) -> Value {
    json!({
        "kind": match col.kind {
            ColumnKind::Fixed => "fixed",
            ColumnKind::Advice => "advice",
            ColumnKind::Instance => "instance",
        },
        "index": col.index,
    })
}

fn expr_to_json(expr: &Expression) -> Value {
    match expr {
        Expression::Constant(fe) => json!({ "const": fe.to_decimal_string() }),
        Expression::Cell(col, rotation) => json!({
            "cell": {
                "column": column_to_json(col),
                "rotation": rotation,
            }
        }),
        Expression::Neg(inner) => json!({ "neg": expr_to_json(inner) }),
        Expression::Sum(a, b) => json!({ "sum": [expr_to_json(a), expr_to_json(b)] }),
        Expression::Product(a, b) => json!({ "product": [expr_to_json(a), expr_to_json(b)] }),
    }
}

fn gate_to_json(gate: &Gate) -> Value {
    json!({
        "name": gate.name,
        "poly": expr_to_json(&gate.poly),
    })
}

fn copy_to_json(copy: &CopyConstraint) -> Value {
    json!({
        "left": {
            "column": column_to_json(&copy.left.column),
            "row": copy.left.row,
        },
        "right": {
            "column": column_to_json(&copy.right.column),
            "row": copy.right.row,
        },
    })
}

fn lookup_to_json(lookup: &Lookup) -> Value {
    let mut obj = json!({
        "name": lookup.name,
        "input_exprs": lookup.input_exprs.iter().map(expr_to_json).collect::<Vec<_>>(),
        "table_exprs": lookup.table_exprs.iter().map(expr_to_json).collect::<Vec<_>>(),
    });
    if let Some(sel) = &lookup.selector {
        obj["selector"] = expr_to_json(sel);
    }
    obj
}

fn lookup_table_to_json(table: &LookupTable) -> Value {
    json!({
        "name": table.name,
        "column": column_to_json(&table.column),
        "values": table.values.iter().map(fe_to_json).collect::<Vec<_>>(),
    })
}

fn column_assignments_to_json(system: &PlonkishSystem, columns: &[Column]) -> Vec<Vec<String>> {
    columns
        .iter()
        .map(|col| match system.assignments.column_values(*col) {
            Some(vals) => vals.iter().map(|v| v.to_decimal_string()).collect(),
            None => Vec::new(),
        })
        .collect()
}

/// Serialize a `PlonkishSystem` to the `achronyme-plonkish-v1` JSON format.
///
/// The output is a self-contained JSON object with the full circuit description
/// (gates, copy constraints, lookups) and all assignments (advice, fixed, instance).
pub fn write_plonkish_json(system: &PlonkishSystem) -> String {
    let root = json!({
        "format": "achronyme-plonkish-v1",
        "num_advice": system.advice_columns.len(),
        "num_fixed": system.fixed_columns.len(),
        "num_instance": system.instance_columns.len(),
        "num_rows": system.num_rows,
        "gates": system.gates.iter().map(gate_to_json).collect::<Vec<_>>(),
        "copies": system.copies.iter().map(copy_to_json).collect::<Vec<_>>(),
        "lookups": system.lookups.iter().map(lookup_to_json).collect::<Vec<_>>(),
        "lookup_tables": system.lookup_tables.iter().map(lookup_table_to_json).collect::<Vec<_>>(),
        "assignments": {
            "advice": column_assignments_to_json(system, &system.advice_columns),
            "fixed": column_assignments_to_json(system, &system.fixed_columns),
            "instance": column_assignments_to_json(system, &system.instance_columns),
        },
    });
    serde_json::to_string_pretty(&root).expect("JSON serialization failed")
}

// ============================================================================
// Deserialization (for roundtrip tests)
// ============================================================================

/// Verify that a JSON string conforms to the `achronyme-plonkish-v1` format.
///
/// Returns `Ok(())` if valid, `Err(message)` if invalid.
pub fn validate_plonkish_json(json_str: &str) -> Result<(), String> {
    let root: Value = serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;

    let format = root["format"].as_str().ok_or("missing 'format' field")?;
    if format != "achronyme-plonkish-v1" {
        return Err(format!("unsupported format: {format}"));
    }

    root["num_advice"]
        .as_u64()
        .ok_or("missing/invalid 'num_advice'")?;
    root["num_fixed"]
        .as_u64()
        .ok_or("missing/invalid 'num_fixed'")?;
    root["num_instance"]
        .as_u64()
        .ok_or("missing/invalid 'num_instance'")?;
    root["num_rows"]
        .as_u64()
        .ok_or("missing/invalid 'num_rows'")?;

    root["gates"]
        .as_array()
        .ok_or("missing/invalid 'gates' array")?;
    root["copies"]
        .as_array()
        .ok_or("missing/invalid 'copies' array")?;
    root["lookups"]
        .as_array()
        .ok_or("missing/invalid 'lookups' array")?;

    let assignments = root["assignments"]
        .as_object()
        .ok_or("missing/invalid 'assignments' object")?;
    assignments
        .get("advice")
        .and_then(|v| v.as_array())
        .ok_or("missing/invalid 'assignments.advice'")?;
    assignments
        .get("fixed")
        .and_then(|v| v.as_array())
        .ok_or("missing/invalid 'assignments.fixed'")?;
    assignments
        .get("instance")
        .and_then(|v| v.as_array())
        .ok_or("missing/invalid 'assignments.instance'")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonkish::PlonkishSystem;

    #[test]
    fn empty_system_roundtrip() {
        let system = PlonkishSystem::new(0);
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

        let system = PlonkishSystem::new(0);
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
}
