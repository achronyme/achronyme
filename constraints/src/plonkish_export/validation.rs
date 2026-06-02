use serde_json::Value;

use memory::FieldElement;

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
        let parsed: Option<FieldElement> = FieldElement::from_decimal_str(s);
        if parsed.is_none() {
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
        let parsed: Option<FieldElement> = FieldElement::from_decimal_str(s);
        if parsed.is_none() {
            return Err(format!("{ctx}.values[{i}]: invalid field element '{s}'"));
        }
    }
    Ok(())
}

fn validate_field_element_str(s: &str, ctx: &str) -> Result<(), String> {
    let parsed: Option<FieldElement> = FieldElement::from_decimal_str(s);
    if parsed.is_none() {
        return Err(format!("{ctx}: invalid field element '{s}'"));
    }
    Ok(())
}

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
