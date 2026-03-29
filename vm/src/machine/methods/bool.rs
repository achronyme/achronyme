//! Bool methods: to_string, to_int

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_FALSE, TAG_TRUE};

pub fn register(registry: &mut PrototypeRegistry) {
    for tag in [TAG_FALSE, TAG_TRUE] {
        registry.register(tag, "to_string", method_to_string);
        registry.register(tag, "to_int", method_to_int);
    }
}

fn is_truthy(v: Value) -> bool {
    v.tag() == TAG_TRUE
}

fn method_to_string(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = if is_truthy(receiver) { "true" } else { "false" };
    let handle = vm
        .heap
        .alloc_string(s.to_string())
        .map_err(|e| RuntimeError::type_mismatch(format!("to_string alloc: {e}")))?;
    Ok(Value::string(handle))
}

fn method_to_int(_vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::int(if is_truthy(receiver) { 1 } else { 0 }))
}
