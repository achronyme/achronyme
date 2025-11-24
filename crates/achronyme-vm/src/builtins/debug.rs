//! Debug and introspection builtin functions

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Describe a value in detail
///
/// Returns a human-readable string description of the value,
/// including type information and structure.
///
/// # Arguments
/// * `_vm` - The VM instance (unused)
/// * `args` - Single argument: the value to describe
///
/// # Returns
/// * `Ok(Value::String)` - Description of the value
/// * `Err(VmError)` - If wrong number of arguments
pub fn vm_describe(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "describe() expects 1 argument, got {}",
            args.len()
        )));
    }

    let description = describe_value(&args[0], 0);
    Ok(Value::String(description))
}

fn describe_value(value: &Value, indent: usize) -> String {
    let indent_str = "  ".repeat(indent);

    match value {
        Value::Number(n) => format!("Number({})", n),
        Value::Boolean(b) => format!("Boolean({})", b),
        Value::String(s) => format!("String({:?})", s),
        Value::Complex(c) => format!("Complex(re: {}, im: {})", c.re, c.im),

        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            if vec.is_empty() {
                "Vector(empty)".to_string()
            } else {
                let items: Vec<String> = vec
                    .iter()
                    .take(10) // Limit to first 10 items
                    .map(|v| describe_value(v, 0))
                    .collect();

                let more = if vec.len() > 10 {
                    format!(" ... and {} more", vec.len() - 10)
                } else {
                    String::new()
                };

                format!(
                    "Vector(length: {}, items: [{}{}])",
                    vec.len(),
                    items.join(", "),
                    more
                )
            }
        }

        Value::Tensor(tensor) => {
            format!(
                "Tensor(shape: {:?}, elements: {})",
                tensor.shape(),
                tensor.data().len()
            )
        }

        Value::ComplexTensor(tensor) => {
            format!(
                "ComplexTensor(shape: {:?}, elements: {})",
                tensor.shape(),
                tensor.data().len()
            )
        }

        Value::Function(func) => {
            use achronyme_types::function::Function;
            match func {
                Function::UserDefined { params, .. } => {
                    let params_str = params.join(", ");
                    format!("Function(UserDefined, params: ({}))", params_str)
                }
                Function::Builtin(name) => {
                    format!("Function(Builtin: {})", name)
                }
                Function::VmClosure(_) => "Function(VmClosure: <bytecode>)".to_string(),
            }
        }

        Value::Record(map_rc) => {
            let map = map_rc.borrow();
            if map.is_empty() {
                "Record(empty)".to_string()
            } else {
                let mut fields: Vec<String> = Vec::new();
                for (key, val) in map.iter().take(10) {
                    // Limit to first 10 fields
                    let val_desc = describe_value(val, indent + 1);
                    fields.push(format!("\n{}  {}: {}", indent_str, key, val_desc));
                }

                let more = if map.len() > 10 {
                    format!("\n{}  ... and {} more fields", indent_str, map.len() - 10)
                } else {
                    String::new()
                };

                format!("Record(fields: {}{}{})", map.len(), fields.join(""), more)
            }
        }

        Value::MutableRef(rc) => {
            let inner = rc.borrow();
            format!("MutableRef({})", describe_value(&inner, indent))
        }

        Value::TailCall(_) => {
            // TailCall should never be visible to user code - it's an internal marker
            "TailCall(internal marker - should not be visible)".to_string()
        }

        Value::EarlyReturn(_) => {
            // EarlyReturn should never be visible to user code - it's an internal marker
            "EarlyReturn(internal marker - should not be visible)".to_string()
        }

        Value::Null => "null".to_string(),

        Value::Generator(_) => "Generator".to_string(),
        Value::Future(_) => "Future".to_string(),

        Value::GeneratorYield(inner) => {
            format!("GeneratorYield({})", describe_value(inner, indent))
        }

        Value::Error {
            message,
            kind,
            source,
        } => {
            let kind_str = kind.as_deref().unwrap_or("Unknown");
            let source_str = match source {
                Some(src) => format!(" (source: {})", describe_value(src, indent + 1)),
                None => String::new(),
            };
            format!("Error({}: {}){}", kind_str, message, source_str)
        }

        Value::LoopBreak(val) => match val {
            Some(inner) => format!("LoopBreak({})", describe_value(inner, indent)),
            None => "LoopBreak(internal marker - should not be visible)".to_string(),
        },

        Value::LoopContinue => "LoopContinue(internal marker - should not be visible)".to_string(),

        Value::Iterator(_) => "Iterator(<opaque state>)".to_string(),

        Value::Builder(_) => "Builder(<opaque state>)".to_string(),

        Value::Range {
            start,
            end,
            inclusive,
        } => {
            let start_str = describe_value(start, 0);
            let end_str = describe_value(end, 0);
            let op = if *inclusive { "..=" } else { ".." };
            format!("Range({}{}{})", start_str, op, end_str)
        }

        Value::BoundMethod { method_name, .. } => {
            format!("BoundMethod({})", method_name)
        }
    }
}
