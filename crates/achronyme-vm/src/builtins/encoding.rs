//! Encoding and Parsing built-ins (JSON, CSV)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// ============================================================================
// JSON
// ============================================================================

/// json_parse(string) -> Value
pub fn vm_json_parse(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(
            "json_parse() expects 1 argument".to_string(),
        ));
    }

    let json_str = match &args[0] {
        Value::String(s) => s,
        _ => {
            return Err(VmError::TypeError {
                operation: "json_parse".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| VmError::Runtime(format!("JSON parse error: {}", e)))?;

    Ok(json_to_value(parsed))
}

/// json_stringify(value, pretty?) -> String
pub fn vm_json_stringify(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "json_stringify() expects at least 1 argument".to_string(),
        ));
    }

    let pretty = if args.len() > 1 {
        match args[1] {
            Value::Boolean(b) => b,
            _ => false,
        }
    } else {
        false
    };

    let json_val = value_to_json(&args[0])?;

    let result = if pretty {
        serde_json::to_string_pretty(&json_val)
    } else {
        serde_json::to_string(&json_val)
    };

    match result {
        Ok(s) => Ok(Value::String(s)),
        Err(e) => Err(VmError::Runtime(format!("JSON stringify error: {}", e))),
    }
}

// --- JSON Helpers ---

fn json_to_value(json: serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                Value::Number(f)
            } else {
                // Handle arbitrary precision or overflow by converting to 0.0 or error?
                // For now, f64 is our numeric type.
                Value::Number(0.0)
            }
        }
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(arr) => {
            let vec: Vec<Value> = arr.into_iter().map(json_to_value).collect();
            Value::Vector(Rc::new(RefCell::new(vec)))
        }
        serde_json::Value::Object(map) => {
            let mut records = HashMap::new();
            for (k, v) in map {
                records.insert(k, json_to_value(v));
            }
            Value::Record(Rc::new(RefCell::new(records)))
        }
    }
}

fn value_to_json(val: &Value) -> Result<serde_json::Value, VmError> {
    match val {
        Value::Null => Ok(serde_json::Value::Null),
        Value::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        Value::Number(n) => {
            // Handle Infinity/NaN because JSON spec doesn't support them
            if n.is_infinite() || n.is_nan() {
                Ok(serde_json::Value::Null)
            } else {
                serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| VmError::Runtime("Invalid number for JSON".to_string()))
            }
        }
        Value::String(s) => Ok(serde_json::Value::String(s.clone())),
        Value::Vector(v) => {
            let v = v.borrow();
            let mut arr = Vec::with_capacity(v.len());
            for item in v.iter() {
                arr.push(value_to_json(item)?);
            }
            Ok(serde_json::Value::Array(arr))
        }
        Value::Record(r) => {
            let r = r.borrow();
            let mut map = serde_json::Map::new();
            for (k, v) in r.iter() {
                map.insert(k.clone(), value_to_json(v)?);
            }
            Ok(serde_json::Value::Object(map))
        }
        // Tensors, Complex, etc. need custom handling or conversion
        Value::Tensor(_t) => {
            // Convert tensor to nested arrays
            // Simplified: flatten for now or implement robust tensor serialization
            // TODO: Better tensor serialization
            Ok(serde_json::Value::String("<Tensor>".to_string()))
        }
        _ => Ok(serde_json::Value::String(format!("{:?}", val))),
    }
}

// ============================================================================
// CSV
// ============================================================================

/// csv_parse(string, has_headers?) -> Vector<Record> or Vector<Vector>
pub fn vm_csv_parse(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "csv_parse() expects at least 1 argument".to_string(),
        ));
    }

    let csv_content = match &args[0] {
        Value::String(s) => s,
        _ => {
            return Err(VmError::TypeError {
                operation: "csv_parse".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let has_headers = if args.len() > 1 {
        match args[1] {
            Value::Boolean(b) => b,
            _ => true, // Default to true
        }
    } else {
        true
    };

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(has_headers)
        .from_reader(csv_content.as_bytes());

    let mut result_rows = Vec::new();

    if has_headers {
        // Return Vector of Records
        let headers = reader
            .headers()
            .map_err(|e| VmError::Runtime(format!("CSV header error: {}", e)))?
            .clone();

        for result in reader.records() {
            let record = result.map_err(|e| VmError::Runtime(format!("CSV parse error: {}", e)))?;
            let mut row_map = HashMap::new();

            for (i, field) in record.iter().enumerate() {
                if let Some(header_name) = headers.get(i) {
                    // Try to parse as number, else string
                    let val = if let Ok(n) = field.parse::<f64>() {
                        Value::Number(n)
                    } else if let Ok(b) = field.parse::<bool>() {
                        Value::Boolean(b)
                    } else {
                        Value::String(field.to_string())
                    };
                    row_map.insert(header_name.to_string(), val);
                }
            }
            result_rows.push(Value::Record(Rc::new(RefCell::new(row_map))));
        }
    } else {
        // Return Vector of Vectors
        for result in reader.records() {
            let record = result.map_err(|e| VmError::Runtime(format!("CSV parse error: {}", e)))?;
            let mut row_vec = Vec::new();

            for field in record.iter() {
                let val = if let Ok(n) = field.parse::<f64>() {
                    Value::Number(n)
                } else if let Ok(b) = field.parse::<bool>() {
                    Value::Boolean(b)
                } else {
                    Value::String(field.to_string())
                };
                row_vec.push(val);
            }
            result_rows.push(Value::Vector(Rc::new(RefCell::new(row_vec))));
        }
    }

    Ok(Value::Vector(Rc::new(RefCell::new(result_rows))))
}
