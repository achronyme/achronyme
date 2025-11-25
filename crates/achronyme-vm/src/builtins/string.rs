//! String manipulation built-in functions
//!
//! This module provides string operations including:
//! - Case conversion: upper, lower
//! - Whitespace: trim, trim_start, trim_end
//! - Search: contains, starts_with, ends_with
//! - Manipulation: replace, split, join, substring
//! - Info: len, char_at

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::{shared, Shared};

// ============================================================================
// Length and Access
// ============================================================================

pub fn vm_len(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "len() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::Number(s.len() as f64)),
        Value::Vector(v) => Ok(Value::Number(v.read().len() as f64)),
        _ => Err(VmError::TypeError {
            operation: "len".to_string(),
            expected: "String or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_char_at(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "char_at() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(s), Value::Number(idx)) => {
            let idx = *idx as usize;
            if let Some(ch) = s.chars().nth(idx) {
                Ok(Value::String(ch.to_string()))
            } else {
                Err(VmError::Runtime(format!(
                    "char_at(): index {} out of bounds for string of length {}",
                    idx,
                    s.chars().count()
                )))
            }
        }
        _ => Err(VmError::TypeError {
            operation: "char_at".to_string(),
            expected: "String, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Case Conversion
// ============================================================================

pub fn vm_upper(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "upper() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(s.to_uppercase())),
        _ => Err(VmError::TypeError {
            operation: "upper".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_lower(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "lower() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(s.to_lowercase())),
        _ => Err(VmError::TypeError {
            operation: "lower".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

// ============================================================================
// Whitespace Handling
// ============================================================================

pub fn vm_trim(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "trim() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(s.trim().to_string())),
        _ => Err(VmError::TypeError {
            operation: "trim".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_trim_start(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "trim_start() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(s.trim_start().to_string())),
        _ => Err(VmError::TypeError {
            operation: "trim_start".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_trim_end(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "trim_end() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(s.trim_end().to_string())),
        _ => Err(VmError::TypeError {
            operation: "trim_end".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

// ============================================================================
// Search Functions
// ============================================================================

pub fn vm_contains(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "contains() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(haystack), Value::String(needle)) => {
            Ok(Value::Boolean(haystack.contains(needle.as_str())))
        }
        _ => Err(VmError::TypeError {
            operation: "contains".to_string(),
            expected: "String, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

pub fn vm_starts_with(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "starts_with() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(s), Value::String(prefix)) => {
            Ok(Value::Boolean(s.starts_with(prefix.as_str())))
        }
        _ => Err(VmError::TypeError {
            operation: "starts_with".to_string(),
            expected: "String, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

pub fn vm_ends_with(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "ends_with() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(s), Value::String(suffix)) => {
            Ok(Value::Boolean(s.ends_with(suffix.as_str())))
        }
        _ => Err(VmError::TypeError {
            operation: "ends_with".to_string(),
            expected: "String, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Manipulation Functions
// ============================================================================

pub fn vm_replace(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "replace() expects 3 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1], &args[2]) {
        (Value::String(s), Value::String(from), Value::String(to)) => {
            Ok(Value::String(s.replace(from.as_str(), to.as_str())))
        }
        _ => Err(VmError::TypeError {
            operation: "replace".to_string(),
            expected: "String, String, String".to_string(),
            got: format!("{:?}, {:?}, {:?}", args[0], args[1], args[2]),
        }),
    }
}

pub fn vm_split(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "split() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(s), Value::String(delimiter)) => {
            let parts: Vec<Value> = s
                .split(delimiter.as_str())
                .map(|part| Value::String(part.to_string()))
                .collect();
            Ok(Value::Vector(shared(parts)))
        }
        _ => Err(VmError::TypeError {
            operation: "split".to_string(),
            expected: "String, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

pub fn vm_join(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "join() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(vec), Value::String(separator)) => {
            let vec_borrowed = vec.read();
            let strings: Result<Vec<String>, VmError> = vec_borrowed
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s.clone()),
                    _ => Err(VmError::TypeError {
                        operation: "join".to_string(),
                        expected: "Vector of Strings".to_string(),
                        got: format!("{:?}", v),
                    }),
                })
                .collect();
            drop(vec_borrowed);
            Ok(Value::String(strings?.join(separator.as_str())))
        }
        _ => Err(VmError::TypeError {
            operation: "join".to_string(),
            expected: "Vector, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

pub fn vm_substring(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "substring() expects 3 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1], &args[2]) {
        (Value::String(s), Value::Number(start), Value::Number(end)) => {
            let start = *start as usize;
            let end = *end as usize;
            let chars: Vec<char> = s.chars().collect();

            if start > chars.len() || end > chars.len() || start > end {
                return Err(VmError::Runtime(format!(
                    "substring(): invalid range [{}..{}] for string of length {}",
                    start,
                    end,
                    chars.len()
                )));
            }

            let substring: String = chars[start..end].iter().collect();
            Ok(Value::String(substring))
        }
        _ => Err(VmError::TypeError {
            operation: "substring".to_string(),
            expected: "String, Number, Number".to_string(),
            got: format!("{:?}, {:?}, {:?}", args[0], args[1], args[2]),
        }),
    }
}

pub fn vm_concat(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "concat() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::String(s1), Value::String(s2)) => Ok(Value::String(format!("{}{}", s1, s2))),
        _ => Err(VmError::TypeError {
            operation: "concat".to_string(),
            expected: "String, String".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}
