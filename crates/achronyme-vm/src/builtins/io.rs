//! I/O built-in functions
//!
//! This module provides input/output operations including:
//! - Output: print, println
//! - Input: input (blocking stdin read)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::io::{self, Write};

// ============================================================================
// Output Functions
// ============================================================================

/// Print value to stdout with newline
pub fn vm_print(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime("print() requires at least 1 argument".to_string()));
    }

    // Print all arguments separated by spaces
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{}", format_value(arg));
    }
    println!();

    Ok(Value::Null)
}

/// Print value to stdout with newline
pub fn vm_println(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        // Just print newline
        println!();
        return Ok(Value::Null);
    }

    // Print all arguments separated by spaces
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{}", format_value(arg));
    }
    println!();

    Ok(Value::Null)
}

// ============================================================================
// Input Functions
// ============================================================================

/// Read a line from stdin
pub fn vm_input(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Optional prompt
    if args.len() == 1 {
        if let Value::String(prompt) = &args[0] {
            print!("{}", prompt);
            io::stdout()
                .flush()
                .map_err(|e| VmError::Runtime(format!("input() failed: {}", e)))?;
        } else {
            return Err(VmError::TypeError {
                operation: "input".to_string(),
                expected: "String (optional)".to_string(),
                got: format!("{:?}", args[0]),
            });
        }
    } else if args.len() > 1 {
        return Err(VmError::Runtime(format!(
            "input() expects 0 or 1 arguments, got {}",
            args.len()
        )));
    }

    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .map_err(|e| VmError::Runtime(format!("input() failed: {}", e)))?;

    // Remove trailing newline
    if buffer.ends_with('\n') {
        buffer.pop();
        if buffer.ends_with('\r') {
            buffer.pop();
        }
    }

    Ok(Value::String(buffer))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Format a value for display
fn format_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Number(n) => {
            // Format numbers nicely
            if n.fract() == 0.0 && n.is_finite() {
                format!("{:.0}", n)
            } else {
                n.to_string()
            }
        }
        Value::String(s) => s.clone(),
        Value::Vector(vec) => {
            let borrowed = vec.borrow();
            let items: Vec<String> = borrowed.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Record(map) => {
            let map = map.borrow();
            let items: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        Value::Function(_) => "<function>".to_string(),
        Value::Generator(_) => "<generator>".to_string(),
        Value::Error { message, .. } => format!("Error: {}", message),
        _ => format!("{:?}", value), // Fallback for other types
    }
}
