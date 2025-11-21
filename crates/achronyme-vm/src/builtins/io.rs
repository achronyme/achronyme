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
pub fn vm_print(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime("print() requires at least 1 argument".to_string()));
    }

    // Print all arguments separated by spaces
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{}", format_value(arg, vm));
    }
    println!();

    Ok(Value::Null)
}

/// Print value to stdout with newline
pub fn vm_println(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
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
        print!("{}", format_value(arg, vm));
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

/// Format a number according to VM precision settings
fn format_number(n: f64, vm: &VM) -> String {
    let rounded = vm.apply_precision(n);

    if vm.is_effectively_zero(rounded) {
        return "0".to_string();
    }

    if let Some(decimals) = vm.get_precision() {
        if decimals == 0 {
            format!("{:.0}", rounded)
        } else {
            format!("{:.prec$}", rounded, prec = decimals as usize)
        }
    } else {
        // Full precision
        if rounded.fract() == 0.0 && rounded.is_finite() {
            format!("{:.0}", rounded)
        } else {
            rounded.to_string()
        }
    }
}

/// Format a complex number with smart formatting
fn format_complex(c: &achronyme_types::complex::Complex, vm: &VM) -> String {
    let re = vm.apply_precision(c.re);
    let im = vm.apply_precision(c.im);

    let re_is_zero = vm.is_effectively_zero(re);
    let im_is_zero = vm.is_effectively_zero(im);
    let epsilon = vm.get_epsilon();

    match (re_is_zero, im_is_zero) {
        (true, true) => "0".to_string(),
        (true, false) => {
            // Pure imaginary: 0 + Xi -> Xi
            if (im - 1.0).abs() < epsilon {
                "i".to_string()
            } else if (im + 1.0).abs() < epsilon {
                "-i".to_string()
            } else {
                format!("{}i", format_number(im, vm))
            }
        }
        (false, true) => {
            // Pure real: X + 0i -> X
            format_number(re, vm)
        }
        (false, false) => {
            // Both parts present: X + Yi or X - Yi
            let re_str = format_number(re, vm);

            // Handle special cases for imaginary coefficient
            let im_str = if (im.abs() - 1.0).abs() < epsilon {
                "i".to_string()
            } else {
                format!("{}i", format_number(im.abs(), vm))
            };

            if im > 0.0 {
                format!("{} + {}", re_str, im_str)
            } else {
                format!("{} - {}", re_str, im_str)
            }
        }
    }
}

/// Format a value for display
fn format_value(value: &Value, vm: &VM) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Number(n) => format_number(*n, vm),
        Value::Complex(c) => format_complex(c, vm),
        Value::String(s) => s.clone(),
        Value::Vector(vec) => {
            let borrowed = vec.borrow();
            let items: Vec<String> = borrowed.iter().map(|v| format_value(v, vm)).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Record(map) => {
            let map = map.borrow();
            let items: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_value(v, vm)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        Value::Function(_) => "<function>".to_string(),
        Value::Generator(_) => "<generator>".to_string(),
        Value::Error { message, .. } => format!("Error: {}", message),
        _ => format!("{:?}", value), // Fallback for other types
    }
}
