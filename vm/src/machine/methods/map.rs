//! Map methods: len, keys, values, entries, contains_key, get, set, remove

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_MAP};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_MAP, "len", method_len);
    registry.register(TAG_MAP, "keys", method_keys);
    registry.register(TAG_MAP, "values", method_values);
    registry.register(TAG_MAP, "entries", method_entries);
    registry.register(TAG_MAP, "contains_key", method_contains_key);
    registry.register(TAG_MAP, "get", method_get);
    registry.register(TAG_MAP, "set", method_set);
    registry.register(TAG_MAP, "remove", method_remove);
}

fn get_map_handle(receiver: Value) -> Result<u32, RuntimeError> {
    receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad map handle".into()))
}

fn resolve_string_arg(vm: &VM, val: Value, method: &str) -> Result<String, RuntimeError> {
    let handle = val.as_handle().ok_or_else(|| {
        RuntimeError::TypeMismatch(format!("{method}: key must be a String"))
    })?;
    vm.heap
        .get_string(handle)
        .cloned()
        .ok_or_else(|| RuntimeError::SystemError(format!("{method}: string missing from heap")))
}

fn method_len(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = get_map_handle(receiver)?;
    let m = vm
        .heap
        .get_map(handle)
        .ok_or(RuntimeError::SystemError("Map missing".into()))?;
    Ok(Value::int(m.len() as i64))
}

fn method_keys(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let map_handle = get_map_handle(receiver)?;
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

/// `map.values()` → list of all values
fn method_values(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let map_handle = get_map_handle(receiver)?;
    let vals: Vec<Value> = {
        let map = vm
            .heap
            .get_map(map_handle)
            .ok_or(RuntimeError::SystemError("Map missing".into()))?;
        map.values().cloned().collect()
    };
    let list_handle = vm.heap.alloc_list(vals);
    Ok(Value::list(list_handle))
}

/// `map.entries()` → list of [key, value] pairs
fn method_entries(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let map_handle = get_map_handle(receiver)?;
    let pairs: Vec<(String, Value)> = {
        let map = vm
            .heap
            .get_map(map_handle)
            .ok_or(RuntimeError::SystemError("Map missing".into()))?;
        map.iter().map(|(k, v)| (k.clone(), *v)).collect()
    };
    vm.heap.lock_gc();
    let mut entry_lists = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let key_handle = vm.heap.alloc_string(k);
        let pair = vec![Value::string(key_handle), v];
        let pair_handle = vm.heap.alloc_list(pair);
        entry_lists.push(Value::list(pair_handle));
    }
    let list_handle = vm.heap.alloc_list(entry_lists);
    vm.heap.unlock_gc();
    Ok(Value::list(list_handle))
}

/// `map.contains_key(key)` → bool
fn method_contains_key(
    vm: &mut VM,
    receiver: Value,
    args: &[Value],
) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "contains_key() takes exactly 1 argument".into(),
        ));
    }
    let map_handle = get_map_handle(receiver)?;
    let key = resolve_string_arg(vm, args[0], "contains_key")?;
    let exists = vm
        .heap
        .get_map(map_handle)
        .ok_or(RuntimeError::SystemError("Map missing".into()))?
        .contains_key(&key);
    Ok(if exists {
        Value::true_val()
    } else {
        Value::false_val()
    })
}

/// `map.get(key, default)` → value or default
fn method_get(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "get() takes exactly 2 arguments (key, default)".into(),
        ));
    }
    let map_handle = get_map_handle(receiver)?;
    let key = resolve_string_arg(vm, args[0], "get")?;
    let val = vm
        .heap
        .get_map(map_handle)
        .ok_or(RuntimeError::SystemError("Map missing".into()))?
        .get(&key)
        .cloned()
        .unwrap_or(args[1]);
    Ok(val)
}

/// `map.set(key, value)` → nil (mutates the map)
fn method_set(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "set() takes exactly 2 arguments (key, value)".into(),
        ));
    }
    let map_handle = get_map_handle(receiver)?;
    let key = resolve_string_arg(vm, args[0], "set")?;
    vm.heap
        .map_insert(map_handle, key, args[1])
        .ok_or(RuntimeError::SystemError("Map missing".into()))?;
    Ok(Value::nil())
}

/// `map.remove(key)` → removed value or nil
fn method_remove(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "remove() takes exactly 1 argument".into(),
        ));
    }
    let map_handle = get_map_handle(receiver)?;
    let key = resolve_string_arg(vm, args[0], "remove")?;
    let removed = vm
        .heap
        .get_map_mut(map_handle)
        .ok_or(RuntimeError::SystemError("Map missing".into()))?
        .remove(&key)
        .unwrap_or(Value::nil());
    Ok(removed)
}
