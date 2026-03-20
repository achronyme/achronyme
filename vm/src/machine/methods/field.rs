//! Field methods: to_int, to_string

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_FIELD};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_FIELD, "to_int", method_to_int);
    registry.register(TAG_FIELD, "to_string", method_to_string);
}

fn method_to_int(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
    let fe = vm
        .heap
        .get_field(handle)
        .ok_or(RuntimeError::SystemError("Field missing".into()))?;
    let canonical = fe.to_canonical();
    if canonical[1] == 0 && canonical[2] == 0 && canonical[3] == 0 {
        Ok(Value::int(canonical[0] as i64))
    } else {
        Err(RuntimeError::TypeMismatch(
            "Field value too large to convert to Int".into(),
        ))
    }
}

fn method_to_string(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad field handle".into()))?;
    let fe = vm
        .heap
        .get_field(handle)
        .ok_or(RuntimeError::SystemError("Field missing".into()))?;
    let s = format!("{}", fe);
    let h = vm.heap.alloc_string(s);
    Ok(Value::string(h))
}
