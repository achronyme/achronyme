//! Type conversion natives: to_string, parse_int, to_field, to_int.

use memory::{FieldElement, Value};
use vm::error::RuntimeError;
use vm::machine::value_ops::ValueOps;
use vm::machine::VM;
use vm::module::{NativeDef, NativeModule};

pub struct ConvModule;

impl NativeModule for ConvModule {
    fn name(&self) -> &'static str {
        "conv"
    }

    fn natives(&self) -> Vec<NativeDef> {
        vec![
            NativeDef {
                name: "to_string",
                func: native_to_string,
                arity: 1,
            },
            NativeDef {
                name: "parse_int",
                func: native_parse_int,
                arity: 1,
            },
            NativeDef {
                name: "to_field",
                func: native_to_field,
                arity: 1,
            },
            NativeDef {
                name: "to_int",
                func: native_to_int,
                arity: 1,
            },
        ]
    }
}

/// `to_string(val)` → String representation of any value.
pub fn native_to_string(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "to_string() takes exactly 1 argument".into(),
        ));
    }
    let s = vm.val_to_string(&args[0]);
    let handle = vm.heap.alloc_string(s);
    Ok(Value::string(handle))
}

/// `parse_int(str)` → Int parsed from string, or error.
pub fn native_parse_int(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "parse_int() takes exactly 1 argument".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "parse_int() expects a String".into(),
        ));
    }
    let handle = args[0]
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?;
    let n: i64 = s
        .trim()
        .parse()
        .map_err(|_| RuntimeError::TypeMismatch(format!("Cannot parse '{}' as integer", s)))?;
    Ok(Value::int(n))
}

/// `to_field(val)` → FieldElement from Int or decimal/hex String.
pub fn native_to_field(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "to_field() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];
    let fe = if val.is_int() {
        let i = val
            .as_int()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad int".into()))?;
        FieldElement::from_i64(i)
    } else if val.is_string() {
        let handle = val
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?
            .clone();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            FieldElement::from_hex_str(hex).ok_or_else(|| {
                RuntimeError::TypeMismatch(format!("Cannot parse '{}' as field element", s))
            })?
        } else {
            FieldElement::from_decimal_str(&s).ok_or_else(|| {
                RuntimeError::TypeMismatch(format!("Cannot parse '{}' as field element", s))
            })?
        }
    } else if val.is_field() {
        // Already a field — return as-is
        return Ok(*val);
    } else {
        return Err(RuntimeError::TypeMismatch(
            "to_field() expects Int, String, or Field".into(),
        ));
    };
    let handle = vm.heap.alloc_field(fe);
    Ok(Value::field(handle))
}

/// `to_int(val)` → Int from Field (canonical value) or String.
pub fn native_to_int(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "to_int() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];
    if val.is_int() {
        Ok(*val)
    } else if val.is_field() {
        let handle = val
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
        let fe = vm
            .heap
            .get_field(handle)
            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
        let canonical = fe.to_canonical();
        // Only convert if it fits in i64 (first limb, rest zero)
        if canonical[1] == 0 && canonical[2] == 0 && canonical[3] == 0 {
            Ok(Value::int(canonical[0] as i64))
        } else {
            Err(RuntimeError::TypeMismatch(
                "Field value too large to convert to Int".into(),
            ))
        }
    } else if val.is_string() {
        let handle = val
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?;
        let n: i64 = s
            .trim()
            .parse()
            .map_err(|_| RuntimeError::TypeMismatch(format!("Cannot parse '{}' as integer", s)))?;
        Ok(Value::int(n))
    } else {
        Err(RuntimeError::TypeMismatch(
            "to_int() expects Int, Field, or String".into(),
        ))
    }
}
