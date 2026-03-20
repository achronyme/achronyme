//! Map methods: len, keys

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_MAP};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_MAP, "len", method_len);
    registry.register(TAG_MAP, "keys", method_keys);
}

fn method_len(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad map handle".into()))?;
    let m = vm
        .heap
        .get_map(handle)
        .ok_or(RuntimeError::SystemError("Map missing".into()))?;
    Ok(Value::int(m.len() as i64))
}

fn method_keys(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let map_handle = receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad map handle".into()))?;
    let keys_raw: Vec<String> = {
        let map = vm
            .heap
            .get_map(map_handle)
            .ok_or(RuntimeError::SystemError("Map corrupted".into()))?;
        map.keys().cloned().collect()
    };
    vm.heap.lock_gc();
    let mut key_values = Vec::with_capacity(keys_raw.len());
    for k in keys_raw {
        let handle = vm.heap.alloc_string(k);
        key_values.push(Value::string(handle));
    }
    let list_handle = vm.heap.alloc_list(key_values);
    vm.heap.unlock_gc();
    Ok(Value::list(list_handle))
}
