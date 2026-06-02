use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use memory::{FieldBackend, FieldElement};

pub(super) fn parse_inputs<F: FieldBackend>(raw: &str) -> Result<HashMap<String, FieldElement<F>>> {
    let mut map = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, val_str) = pair.split_once('=').context(format!(
            "invalid input pair: {pair:?} (expected name=value)"
        ))?;
        let val = parse_field_value::<F>(name, val_str)?;
        map.insert(name.to_string(), val);
    }
    Ok(map)
}

fn parse_field_value<F: FieldBackend>(name: &str, val_str: &str) -> Result<FieldElement<F>> {
    let val_str = val_str.trim();
    if val_str.starts_with("0x") || val_str.starts_with("0X") {
        FieldElement::<F>::from_hex_str(val_str)
            .context(format!("invalid hex value for `{name}`: {val_str:?}"))
    } else if let Some(digits) = val_str.strip_prefix('-') {
        let abs = FieldElement::<F>::from_decimal_str(digits)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))?;
        Ok(abs.neg())
    } else {
        FieldElement::<F>::from_decimal_str(val_str)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))
    }
}

pub(super) fn parse_inputs_toml<F: FieldBackend>(
    path: &str,
) -> Result<HashMap<String, FieldElement<F>>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("cannot read input file: {path}"))?;
    let table: toml::Table = content
        .parse()
        .with_context(|| format!("invalid TOML in {path}"))?;

    let mut map = HashMap::new();
    for (key, value) in &table {
        match value {
            toml::Value::String(s) => {
                map.insert(key.clone(), parse_field_value::<F>(key, s)?);
            }
            toml::Value::Integer(n) => {
                let fe = if *n < 0 {
                    FieldElement::<F>::from_decimal_str(&n.unsigned_abs().to_string())
                        .context(format!("invalid integer for `{key}`: {n}"))?
                        .neg()
                } else {
                    FieldElement::<F>::from_u64(*n as u64)
                };
                map.insert(key.clone(), fe);
            }
            toml::Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    let elem_name = format!("{key}_{i}");
                    match elem {
                        toml::Value::String(s) => {
                            map.insert(elem_name.clone(), parse_field_value::<F>(&elem_name, s)?);
                        }
                        toml::Value::Integer(n) => {
                            let fe = if *n < 0 {
                                FieldElement::<F>::from_decimal_str(&n.unsigned_abs().to_string())
                                    .context(format!("invalid integer for `{elem_name}`: {n}"))?
                                    .neg()
                            } else {
                                FieldElement::<F>::from_u64(*n as u64)
                            };
                            map.insert(elem_name, fe);
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "array element {key}[{i}] must be a string or integer"
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "input `{key}` must be a string, integer, or array"
                ));
            }
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------
