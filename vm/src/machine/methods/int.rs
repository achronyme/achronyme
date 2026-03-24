//! Int methods: abs, min, max, pow, to_field, to_string

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{FieldElement, Value, TAG_INT};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_INT, "abs", method_abs);
    registry.register(TAG_INT, "min", method_min);
    registry.register(TAG_INT, "max", method_max);
    registry.register(TAG_INT, "pow", method_pow);
    registry.register(TAG_INT, "to_field", method_to_field);
    registry.register(TAG_INT, "to_string", method_to_string);
}

fn method_abs(_vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let n = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("abs: expected Int".into()))?;
    Ok(Value::int(n.abs()))
}

fn method_min(_vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "min() takes exactly 1 argument".into(),
        ));
    }
    let a = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("min: expected Int".into()))?;
    let b = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("min: argument must be Int".into()))?;
    Ok(Value::int(a.min(b)))
}

fn method_max(_vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "max() takes exactly 1 argument".into(),
        ));
    }
    let a = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("max: expected Int".into()))?;
    let b = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("max: argument must be Int".into()))?;
    Ok(Value::int(a.max(b)))
}

fn method_pow(_vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "pow() takes exactly 1 argument".into(),
        ));
    }
    let base = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("pow: expected Int".into()))?;
    let exp = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("pow: exponent must be Int".into()))?;
    if exp < 0 {
        return Err(RuntimeError::TypeMismatch(
            "pow() exponent must be non-negative".into(),
        ));
    }
    if exp > u32::MAX as i64 {
        return Err(RuntimeError::TypeMismatch(
            "pow() exponent too large".into(),
        ));
    }
    let result = (base as i128).pow(exp as u32);
    if result > i64::MAX as i128 || result < i64::MIN as i128 {
        return Err(RuntimeError::TypeMismatch(
            "pow() result overflows Int range".into(),
        ));
    }
    Ok(Value::int(result as i64))
}

fn method_to_field(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let n = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("to_field: expected Int".into()))?;
    let fe = FieldElement::from_i64(n);
    let handle = vm.heap.alloc_field(fe)?;
    Ok(Value::field(handle))
}

fn method_to_string(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let n = receiver
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("to_string: expected Int".into()))?;
    let s = n.to_string();
    let handle = vm.heap.alloc_string(s)?;
    Ok(Value::string(handle))
}
