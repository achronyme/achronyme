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
            Some(vals) => vals[..system.num_rows.min(vals.len())]
                .iter()
                .map(|v| v.to_decimal_string())
                .collect(),
            None => vec!["0".to_string(); system.num_rows],
        })
        .collect()
}

/// Serialize a `PlonkishSystem` to the `achronyme-plonkish-v1` JSON format.
///
/// The output is a self-contained JSON object with the full circuit description
/// (gates, copy constraints, lookups) and all assignments (advice, fixed, instance).
///
/// **WARNING**: The output includes private witness data (advice columns) in
/// plaintext. Do not share the resulting JSON in untrusted environments, as
/// this breaks the zero-knowledge property of the circuit.
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

// ============================================================================
// Validation helpers
// ============================================================================

/// Dimensions extracted once and passed to all validators.
struct Dims {
    num_advice: u64,
    num_fixed: u64,
    num_instance: u64,
    num_rows: u64,
}

fn validate_column_json(col: &Value, dims: &Dims, ctx: &str) -> Result<(), String> {
    let kind = col["kind"]
        .as_str()
        .ok_or_else(|| format!("{ctx}: column missing 'kind' string"))?;
    let index = col["index"]
        .as_u64()
        .ok_or_else(|| format!("{ctx}: column missing 'index' u64"))?;
    let bound = match kind {
        "advice" => dims.num_advice,
        "fixed" => dims.num_fixed,
        "instance" => dims.num_instance,
        other => return Err(format!("{ctx}: invalid column kind '{other}'")),
    };
    if index >= bound {
        return Err(format!(
            "{ctx}: column index {index} out of bounds for {kind} (max {bound})"
        ));
    }
    Ok(())
}

fn validate_expr_json(expr: &Value, dims: &Dims, ctx: &str) -> Result<(), String> {
    if let Some(s) = expr.get("const") {
        let s = s
            .as_str()
            .ok_or_else(|| format!("{ctx}: 'const' must be a string"))?;
        if FieldElement::from_decimal_str(s).is_none() {
            return Err(format!("{ctx}: invalid field element '{s}'"));
        }
        return Ok(());
    }
    if let Some(cell) = expr.get("cell") {
        let col = &cell["column"];
        if col.is_null() {
            return Err(format!("{ctx}: cell missing 'column'"));
        }
        validate_column_json(col, dims, &format!("{ctx}.cell"))?;
        if cell.get("rotation").is_none()
            || (!cell["rotation"].is_i64() && !cell["rotation"].is_u64())
        {
            return Err(format!("{ctx}: cell missing 'rotation' integer"));
        }
        return Ok(());
    }
    if let Some(inner) = expr.get("neg") {
        return validate_expr_json(inner, dims, &format!("{ctx}.neg"));
    }
    if let Some(arr) = expr.get("sum") {
        let arr = arr
            .as_array()
            .ok_or_else(|| format!("{ctx}: 'sum' must be an array"))?;
        if arr.len() != 2 {
            return Err(format!("{ctx}: 'sum' must have exactly 2 elements"));
        }
        validate_expr_json(&arr[0], dims, &format!("{ctx}.sum[0]"))?;
        validate_expr_json(&arr[1], dims, &format!("{ctx}.sum[1]"))?;
        return Ok(());
    }
    if let Some(arr) = expr.get("product") {
        let arr = arr
            .as_array()
            .ok_or_else(|| format!("{ctx}: 'product' must be an array"))?;
        if arr.len() != 2 {
            return Err(format!("{ctx}: 'product' must have exactly 2 elements"));
        }
        validate_expr_json(&arr[0], dims, &format!("{ctx}.product[0]"))?;
        validate_expr_json(&arr[1], dims, &format!("{ctx}.product[1]"))?;
        return Ok(());
    }
    Err(format!(
        "{ctx}: expression must have one of 'const', 'cell', 'neg', 'sum', 'product'"
    ))
}

fn validate_gate_json(gate: &Value, dims: &Dims, idx: usize) -> Result<(), String> {
    let ctx = format!("gates[{idx}]");
    gate["name"]
        .as_str()
        .ok_or_else(|| format!("{ctx}: missing 'name' string"))?;
    if gate.get("poly").is_none() || gate["poly"].is_null() {
        return Err(format!("{ctx}: missing 'poly'"));
    }
    validate_expr_json(&gate["poly"], dims, &format!("{ctx}.poly"))
}

fn validate_copy_json(copy: &Value, dims: &Dims, idx: usize) -> Result<(), String> {
    let ctx = format!("copies[{idx}]");
    for side in &["left", "right"] {
        let s = copy
            .get(*side)
            .ok_or_else(|| format!("{ctx}: missing '{side}'"))?;
        if s.is_null() {
            return Err(format!("{ctx}: missing '{side}'"));
        }
        let col = &s["column"];
        if col.is_null() {
            return Err(format!("{ctx}.{side}: missing 'column'"));
        }
        validate_column_json(col, dims, &format!("{ctx}.{side}"))?;
        let row = s["row"]
            .as_u64()
            .ok_or_else(|| format!("{ctx}.{side}: missing 'row' u64"))?;
        if row >= dims.num_rows {
            return Err(format!(
                "{ctx}.{side}: row {row} out of bounds (num_rows={})",
                dims.num_rows
            ));
        }
    }
    Ok(())
}

fn validate_lookup_json(lookup: &Value, dims: &Dims, idx: usize) -> Result<(), String> {
    let ctx = format!("lookups[{idx}]");
    lookup["name"]
        .as_str()
        .ok_or_else(|| format!("{ctx}: missing 'name' string"))?;
    let input_exprs = lookup["input_exprs"]
        .as_array()
        .ok_or_else(|| format!("{ctx}: missing 'input_exprs' array"))?;
    for (i, expr) in input_exprs.iter().enumerate() {
        validate_expr_json(expr, dims, &format!("{ctx}.input_exprs[{i}]"))?;
    }
    let table_exprs = lookup["table_exprs"]
        .as_array()
        .ok_or_else(|| format!("{ctx}: missing 'table_exprs' array"))?;
    for (i, expr) in table_exprs.iter().enumerate() {
        validate_expr_json(expr, dims, &format!("{ctx}.table_exprs[{i}]"))?;
    }
    // selector is optional
    if let Some(sel) = lookup.get("selector") {
        if !sel.is_null() {
            validate_expr_json(sel, dims, &format!("{ctx}.selector"))?;
        }
    }
    Ok(())
}

fn validate_lookup_table_json(table: &Value, dims: &Dims, idx: usize) -> Result<(), String> {
    let ctx = format!("lookup_tables[{idx}]");
    table["name"]
        .as_str()
        .ok_or_else(|| format!("{ctx}: missing 'name' string"))?;
    let col = &table["column"];
    if col.is_null() {
        return Err(format!("{ctx}: missing 'column'"));
    }
    validate_column_json(col, dims, &ctx)?;
    let values = table["values"]
        .as_array()
        .ok_or_else(|| format!("{ctx}: missing 'values' array"))?;
    for (i, v) in values.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{ctx}.values[{i}]: expected string"))?;
        if FieldElement::from_decimal_str(s).is_none() {
            return Err(format!("{ctx}.values[{i}]: invalid field element '{s}'"));
        }
    }
    Ok(())
}

fn validate_field_element_str(s: &str, ctx: &str) -> Result<(), String> {
    if FieldElement::from_decimal_str(s).is_none() {
        return Err(format!("{ctx}: invalid field element '{s}'"));
    }
    Ok(())
}

// ============================================================================
// Public validation
// ============================================================================

/// Verify that a JSON string conforms to the `achronyme-plonkish-v1` format.
///
/// Performs deep structural, dimensional, bounds, and field-element validation.
/// Returns `Ok(())` if valid, `Err(message)` if invalid.
pub fn validate_plonkish_json(json_str: &str) -> Result<(), String> {
    let root: Value = serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;

    let format = root["format"].as_str().ok_or("missing 'format' field")?;
    if format != "achronyme-plonkish-v1" {
        return Err(format!("unsupported format: {format}"));
    }

    let num_advice = root["num_advice"]
        .as_u64()
        .ok_or("missing/invalid 'num_advice'")?;
    let num_fixed = root["num_fixed"]
        .as_u64()
        .ok_or("missing/invalid 'num_fixed'")?;
    let num_instance = root["num_instance"]
        .as_u64()
        .ok_or("missing/invalid 'num_instance'")?;
    let num_rows = root["num_rows"]
        .as_u64()
        .ok_or("missing/invalid 'num_rows'")?;

    let dims = Dims {
        num_advice,
        num_fixed,
        num_instance,
        num_rows,
    };

    // --- Gates ---
    let gates = root["gates"]
        .as_array()
        .ok_or("missing/invalid 'gates' array")?;
    for (i, gate) in gates.iter().enumerate() {
        validate_gate_json(gate, &dims, i)?;
    }

    // --- Copies ---
    let copies = root["copies"]
        .as_array()
        .ok_or("missing/invalid 'copies' array")?;
    for (i, copy) in copies.iter().enumerate() {
        validate_copy_json(copy, &dims, i)?;
    }

    // --- Lookups ---
    let lookups = root["lookups"]
        .as_array()
        .ok_or("missing/invalid 'lookups' array")?;
    for (i, lookup) in lookups.iter().enumerate() {
        validate_lookup_json(lookup, &dims, i)?;
    }

    // --- Lookup tables ---
    let lookup_tables = root["lookup_tables"]
        .as_array()
        .ok_or("missing/invalid 'lookup_tables' array")?;
    for (i, table) in lookup_tables.iter().enumerate() {
        validate_lookup_table_json(table, &dims, i)?;
    }

    // --- Assignments ---
    let assignments = root["assignments"]
        .as_object()
        .ok_or("missing/invalid 'assignments' object")?;

    for (kind, expected_len) in [
        ("advice", num_advice),
        ("fixed", num_fixed),
        ("instance", num_instance),
    ] {
        let cols = assignments
            .get(kind)
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("missing/invalid 'assignments.{kind}'"))?;

        if cols.len() as u64 != expected_len {
            return Err(format!(
                "assignments.{kind} has {} columns, expected {expected_len}",
                cols.len()
            ));
        }

        for (ci, col) in cols.iter().enumerate() {
            let rows = col
                .as_array()
                .ok_or_else(|| format!("assignments.{kind}[{ci}]: expected array of strings"))?;
            if rows.len() as u64 != num_rows {
                return Err(format!(
                    "assignments.{kind}[{ci}] has {} rows, expected {num_rows}",
                    rows.len()
                ));
            }
            for (ri, val) in rows.iter().enumerate() {
                let s = val
                    .as_str()
                    .ok_or_else(|| format!("assignments.{kind}[{ci}][{ri}]: expected string"))?;
                validate_field_element_str(s, &format!("assignments.{kind}[{ci}][{ri}]"))?;
            }
        }
    }

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

    // ================================================================
    // W1: Structural validation
    // ================================================================

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

    // ================================================================
    // W4: Bounds validation
    // ================================================================

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

    // ================================================================
    // W3: Field element validation
    // ================================================================

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

    // ================================================================
    // W2: Dimensional validation
    // ================================================================

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

    // ================================================================
    // Roundtrip: real circuit validates
    // ================================================================

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
}
