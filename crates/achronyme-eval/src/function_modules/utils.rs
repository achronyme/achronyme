/// Utility functions for Achronyme
///
/// This module provides essential utility functions for:
/// - Output: print() for displaying values
/// - Type inspection: typeof() for getting type names
/// - String conversion: str() for converting values to strings

use crate::functions::FunctionRegistry;
use achronyme_types::value::Value;
use achronyme_types::Environment;

pub fn register_functions(registry: &mut FunctionRegistry) {
    // Output function
    registry.register("print", print, -1); // Variadic: 1+ args

    // Type inspection (renamed from type to typeof to free 'type' as keyword)
    registry.register("typeof", type_of, 1);

    // String conversion
    registry.register("str", to_string, 1);

    // IEEE 754 special value checks
    registry.register("isnan", is_nan, 1);
    registry.register("isinf", is_inf, 1);
    registry.register("isfinite", is_finite, 1);
}

// ============================================================================
// Output Functions
// ============================================================================

/// Print values to standard output
///
/// Accepts one or more arguments and prints them separated by spaces.
/// Always prints a newline at the end.
///
/// Examples:
/// - print(42) => prints "42\n"
/// - print("hello", "world") => prints "hello world\n"
/// - print([1, 2, 3]) => prints "[1, 2, 3]\n"
///
/// Returns: The last value printed (or Unit/void equivalent)
fn print(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    if args.is_empty() {
        return Err("print() requires at least 1 argument".to_string());
    }

    let formatted_values: Vec<String> = args
        .iter()
        .map(|v| format_value(v))
        .collect();

    println!("{}", formatted_values.join(" "));

    // Return the last value (useful for chaining)
    Ok(args[args.len() - 1].clone())
}

// ============================================================================
// Type Inspection Functions
// ============================================================================

/// Get the type name of a value
///
/// Returns a string describing the type of the value.
///
/// Examples:
/// - typeof(42) => "Number"
/// - typeof("hello") => "String"
/// - typeof([1, 2, 3]) => "Tensor"
/// - typeof(true) => "Boolean"
fn type_of(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    let type_name = get_type_name(&args[0]);
    Ok(Value::String(type_name))
}

/// Get the type name for a value
fn get_type_name(value: &Value) -> String {
    match value {
        Value::Number(_) => "Number".to_string(),
        Value::Boolean(_) => "Boolean".to_string(),
        Value::Complex(_) => "Complex".to_string(),
        Value::String(_) => "String".to_string(),
        Value::Vector(_) => "Vector".to_string(),
        Value::Tensor(_) => "Tensor".to_string(),
        Value::ComplexTensor(_) => "ComplexTensor".to_string(),
        Value::Function(_) => "Function".to_string(),
        Value::Record(_) => "Record".to_string(),
        Value::Edge { .. } => "Edge".to_string(),
        Value::TailCall(_) => "TailCall".to_string(),
        Value::EarlyReturn(_) => "EarlyReturn".to_string(),
        Value::MutableRef(rc) => {
            // For mutable refs, show the type of the inner value
            match rc.try_borrow() {
                Ok(inner) => format!("MutableRef<{}>", get_type_name(&inner)),
                Err(_) => "MutableRef<?>".to_string(),
            }
        }
        Value::Null => "null".to_string(),
        Value::Generator(_) => "Generator".to_string(),
        Value::GeneratorYield(_) => "GeneratorYield".to_string(),
        Value::Error { .. } => "Error".to_string(),
        Value::LoopBreak(_) => "LoopBreak".to_string(),
        Value::LoopContinue => "LoopContinue".to_string(),
    }
}

// ============================================================================
// String Conversion Functions
// ============================================================================

/// Convert a value to its string representation
///
/// Examples:
/// - str(42) => "42"
/// - str(3.14) => "3.14"
/// - str(true) => "true"
/// - str([1, 2, 3]) => "[1, 2, 3]"
fn to_string(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    Ok(Value::String(format_value(&args[0])))
}

// ============================================================================
// IEEE 754 Special Value Functions
// ============================================================================

/// Check if a value is NaN (Not a Number)
///
/// Returns true if the value is NaN, false otherwise.
/// Works on numbers, vectors, and tensors (element-wise).
///
/// Examples:
/// - isnan(NaN) => true
/// - isnan(0/0) => true
/// - isnan(42) => false
/// - isnan(Infinity) => false
/// - isnan([1, NaN, 3]) => [false, true, false]
fn is_nan(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_nan())),
        Value::Vector(vec) => {
            let result: Result<Vec<Value>, String> = vec
                .iter()
                .map(|v| match v {
                    Value::Number(n) => Ok(Value::Boolean(n.is_nan())),
                    _ => Err("isnan() can only be applied to numeric vectors".to_string()),
                })
                .collect();
            Ok(Value::Vector(result?))
        }
        Value::Tensor(tensor) => {
            let result: Vec<Value> = tensor
                .data()
                .iter()
                .map(|n| Value::Boolean(n.is_nan()))
                .collect();
            Ok(Value::Vector(result))
        }
        _ => Err("isnan() requires a number, vector, or tensor".to_string()),
    }
}

/// Check if a value is infinite (positive or negative infinity)
///
/// Returns true if the value is Infinity or -Infinity, false otherwise.
/// Works on numbers, vectors, and tensors (element-wise).
///
/// Examples:
/// - isinf(Infinity) => true
/// - isinf(-Infinity) => true
/// - isinf(1/0) => true
/// - isinf(42) => false
/// - isinf(NaN) => false
/// - isinf([1, Infinity, 3]) => [false, true, false]
fn is_inf(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_infinite())),
        Value::Vector(vec) => {
            let result: Result<Vec<Value>, String> = vec
                .iter()
                .map(|v| match v {
                    Value::Number(n) => Ok(Value::Boolean(n.is_infinite())),
                    _ => Err("isinf() can only be applied to numeric vectors".to_string()),
                })
                .collect();
            Ok(Value::Vector(result?))
        }
        Value::Tensor(tensor) => {
            let result: Vec<Value> = tensor
                .data()
                .iter()
                .map(|n| Value::Boolean(n.is_infinite()))
                .collect();
            Ok(Value::Vector(result))
        }
        _ => Err("isinf() requires a number, vector, or tensor".to_string()),
    }
}

/// Check if a value is finite (not NaN and not infinite)
///
/// Returns true if the value is a finite number, false otherwise.
/// Works on numbers, vectors, and tensors (element-wise).
///
/// Examples:
/// - isfinite(42) => true
/// - isfinite(3.14) => true
/// - isfinite(Infinity) => false
/// - isfinite(-Infinity) => false
/// - isfinite(NaN) => false
/// - isfinite([1, Infinity, NaN]) => [true, false, false]
fn is_finite(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_finite())),
        Value::Vector(vec) => {
            let result: Result<Vec<Value>, String> = vec
                .iter()
                .map(|v| match v {
                    Value::Number(n) => Ok(Value::Boolean(n.is_finite())),
                    _ => Err("isfinite() can only be applied to numeric vectors".to_string()),
                })
                .collect();
            Ok(Value::Vector(result?))
        }
        Value::Tensor(tensor) => {
            let result: Vec<Value> = tensor
                .data()
                .iter()
                .map(|n| Value::Boolean(n.is_finite()))
                .collect();
            Ok(Value::Vector(result))
        }
        _ => Err("isfinite() requires a number, vector, or tensor".to_string()),
    }
}

/// Format a value for display
fn format_value(value: &Value) -> String {
    match value {
        Value::Number(n) => {
            // Handle IEEE 754 special values first
            if n.is_nan() {
                "NaN".to_string()
            } else if n.is_infinite() {
                if n.is_sign_positive() {
                    "Infinity".to_string()
                } else {
                    "-Infinity".to_string()
                }
            } else if n.fract() == 0.0 {
                // Format integers nicely (remove .0)
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Value::Boolean(b) => format!("{}", b),
        Value::Complex(c) => {
            // Format: a+bi or a-bi
            if c.im >= 0.0 {
                format!("{}+{}i", c.re, c.im)
            } else {
                format!("{}{}i", c.re, c.im)
            }
        }
        Value::String(s) => s.clone(),
        Value::Vector(vec) => {
            let elements: Vec<String> = vec.iter().map(format_value).collect();
            format!("[{}]", elements.join(", "))
        }
        Value::Tensor(tensor) => {
            // Format tensor based on shape
            if tensor.is_vector() {
                // 1D tensor - show as array
                let elements: Vec<String> = tensor
                    .data()
                    .iter()
                    .map(|&n| {
                        if n.is_nan() {
                            "NaN".to_string()
                        } else if n.is_infinite() {
                            if n.is_sign_positive() {
                                "Infinity".to_string()
                            } else {
                                "-Infinity".to_string()
                            }
                        } else if n.fract() == 0.0 {
                            format!("{}", n as i64)
                        } else {
                            format!("{}", n)
                        }
                    })
                    .collect();
                format!("[{}]", elements.join(", "))
            } else {
                // Multi-dimensional tensor
                format!("Tensor{:?}", tensor.shape())
            }
        }
        Value::ComplexTensor(tensor) => {
            if tensor.is_vector() {
                let elements: Vec<String> = tensor
                    .data()
                    .iter()
                    .map(|c| {
                        if c.im >= 0.0 {
                            format!("{}+{}i", c.re, c.im)
                        } else {
                            format!("{}{}i", c.re, c.im)
                        }
                    })
                    .collect();
                format!("[{}]", elements.join(", "))
            } else {
                format!("ComplexTensor{:?}", tensor.shape())
            }
        }
        Value::Function(f) => {
            match f.builtin_name() {
                Some(name) => format!("<function:{}>", name),
                None => "<function:lambda>".to_string(),
            }
        }
        Value::Record(map) => {
            if map.is_empty() {
                "{}".to_string()
            } else {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
        }
        Value::Edge { from, to, directed, properties } => {
            let dir = if *directed { "->" } else { "--" };
            if properties.is_empty() {
                format!("{} {} {}", from, dir, to)
            } else {
                format!("{} {} {} {:?}", from, dir, to, properties)
            }
        }
        Value::TailCall(_) => "<tail-call>".to_string(),
        Value::EarlyReturn(_) => "<early-return>".to_string(),
        Value::MutableRef(rc) => {
            match rc.try_borrow() {
                Ok(inner) => format!("mut {}", format_value(&inner)),
                Err(_) => "mut <borrowed>".to_string(),
            }
        }
        Value::Null => "null".to_string(),
        Value::Generator(_) => "<generator>".to_string(),
        Value::GeneratorYield(_) => "<generator-yield>".to_string(),
        Value::Error { message, kind, .. } => {
            match kind {
                Some(k) => format!("Error({}: {})", k, message),
                None => format!("Error({})", message),
            }
        }
        Value::LoopBreak(_) => "<loop-break>".to_string(),
        Value::LoopContinue => "<loop-continue>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_number() {
        let mut env = Environment::new();
        let args = vec![Value::Number(42.0)];
        let result = type_of(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("Number".to_string()));
    }

    #[test]
    fn test_type_string() {
        let mut env = Environment::new();
        let args = vec![Value::String("hello".to_string())];
        let result = type_of(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("String".to_string()));
    }

    #[test]
    fn test_type_boolean() {
        let mut env = Environment::new();
        let args = vec![Value::Boolean(true)];
        let result = type_of(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("Boolean".to_string()));
    }

    #[test]
    fn test_str_number() {
        let mut env = Environment::new();
        let args = vec![Value::Number(42.0)];
        let result = to_string(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("42".to_string()));
    }

    #[test]
    fn test_str_float() {
        let mut env = Environment::new();
        let args = vec![Value::Number(3.14)];
        let result = to_string(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("3.14".to_string()));
    }

    #[test]
    fn test_str_string() {
        let mut env = Environment::new();
        let args = vec![Value::String("hello".to_string())];
        let result = to_string(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("hello".to_string()));
    }

    #[test]
    fn test_str_boolean() {
        let mut env = Environment::new();
        let args = vec![Value::Boolean(true)];
        let result = to_string(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("true".to_string()));
    }

    #[test]
    fn test_str_vector() {
        let mut env = Environment::new();
        let args = vec![Value::Vector(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
        ])];
        let result = to_string(&args, &mut env).unwrap();
        assert_eq!(result, Value::String("[1, 2, 3]".to_string()));
    }

    #[test]
    fn test_format_number_integer() {
        let value = Value::Number(42.0);
        assert_eq!(format_value(&value), "42");
    }

    #[test]
    fn test_format_number_float() {
        let value = Value::Number(3.14);
        assert_eq!(format_value(&value), "3.14");
    }
}
