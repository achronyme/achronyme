//! Environment variable built-ins

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::rc::Rc;

/// env_get(key) -> String | Null
pub fn vm_env_get(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("env_get() expects 1 argument".to_string()));
    }

    let key = match &args[0] {
        Value::String(s) => s,
        _ => {
            return Err(VmError::TypeError {
                operation: "env_get".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    match env::var(key) {
        Ok(val) => Ok(Value::String(val)),
        Err(_) => Ok(Value::Null),
    }
}

/// env_set(key, value) -> Null
pub fn vm_env_set(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(
            "env_set() expects 2 arguments".to_string(),
        ));
    }

    let key = match &args[0] {
        Value::String(s) => s,
        _ => {
            return Err(VmError::TypeError {
                operation: "env_set".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let value = match &args[1] {
        Value::String(s) => s,
        _ => {
            return Err(VmError::TypeError {
                operation: "env_set".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    env::set_var(key, value);
    Ok(Value::Null)
}

/// env_vars() -> Record
pub fn vm_env_vars(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime(
            "env_vars() expects 0 arguments".to_string(),
        ));
    }

    let mut vars_map = HashMap::new();
    for (key, value) in env::vars() {
        vars_map.insert(key, Value::String(value));
    }

    Ok(Value::Record(Rc::new(RefCell::new(vars_map))))
}

/// env_load(path?) -> Boolean
/// Loads environment variables from a file (defaults to ".env").
/// Returns true if file was found and loaded, false otherwise.
pub fn vm_env_load(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let path = if args.is_empty() {
        ".env".to_string()
    } else if args.len() == 1 {
        match &args[0] {
            Value::String(s) => s.clone(),
            _ => {
                return Err(VmError::TypeError {
                    operation: "env_load".to_string(),
                    expected: "String".to_string(),
                    got: format!("{:?}", args[0]),
                })
            }
        }
    } else {
        return Err(VmError::Runtime(
            "env_load() expects 0 or 1 argument".to_string(),
        ));
    };

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Ok(Value::Boolean(false)), // File not found is not a runtime error here, just false
    };

    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        if let Ok(l) = line {
            let trimmed = l.trim();
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let mut value = value.trim();

                // Remove optional quotes
                if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value = &value[1..value.len() - 1];
                }

                if !key.is_empty() {
                    env::set_var(key, value);
                }
            }
        }
    }

    Ok(Value::Boolean(true))
}
