use serde_json::{json, Value};

use crate::plonkish::{
    Column, ColumnKind, CopyConstraint, Expression, Gate, Lookup, LookupTable, PlonkishSystem,
};
use memory::{FieldBackend, FieldElement};

fn fe_to_json<F: FieldBackend>(fe: &FieldElement<F>) -> Value {
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

fn expr_to_json<F: FieldBackend>(expr: &Expression<F>) -> Value {
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

fn gate_to_json<F: FieldBackend>(gate: &Gate<F>) -> Value {
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

fn lookup_to_json<F: FieldBackend>(lookup: &Lookup<F>) -> Value {
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

fn lookup_table_to_json<F: FieldBackend>(table: &LookupTable<F>) -> Value {
    json!({
        "name": table.name,
        "column": column_to_json(&table.column),
        "values": table.values.iter().map(fe_to_json).collect::<Vec<_>>(),
    })
}

fn column_assignments_to_json<F: FieldBackend>(
    system: &PlonkishSystem<F>,
    columns: &[Column],
) -> Vec<Vec<String>> {
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
pub fn write_plonkish_json<F: FieldBackend>(system: &PlonkishSystem<F>) -> String {
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
