//! String methods: len, starts_with, ends_with, contains, split, trim,
//! replace, to_upper, to_lower, chars, index_of, substring, repeat

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_STRING};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_STRING, "len", method_len);
    registry.register(TAG_STRING, "starts_with", method_starts_with);
    registry.register(TAG_STRING, "ends_with", method_ends_with);
    registry.register(TAG_STRING, "contains", method_contains);
    registry.register(TAG_STRING, "split", method_split);
    registry.register(TAG_STRING, "trim", method_trim);
    registry.register(TAG_STRING, "replace", method_replace);
    registry.register(TAG_STRING, "to_upper", method_to_upper);
    registry.register(TAG_STRING, "to_lower", method_to_lower);
    registry.register(TAG_STRING, "chars", method_chars);
    registry.register(TAG_STRING, "index_of", method_index_of);
    registry.register(TAG_STRING, "substring", method_substring);
    registry.register(TAG_STRING, "repeat", method_repeat);
    registry.register(TAG_STRING, "to_string", method_to_string);
}

/// Helper: get owned string from receiver handle.
fn get_string(vm: &VM, receiver: Value) -> Result<String, RuntimeError> {
    let handle = receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
    Ok(vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone())
}

/// Helper: extract string from a Value argument.
fn arg_string(vm: &VM, val: &Value, method: &str) -> Result<String, RuntimeError> {
    if !val.is_string() {
        return Err(RuntimeError::TypeMismatch(format!(
            "{method}: argument must be a String"
        )));
    }
    let handle = val
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
    Ok(vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone())
}

fn method_len(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = get_string(vm, receiver)?;
    Ok(Value::int(s.chars().count() as i64))
}

fn method_starts_with(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "starts_with() takes exactly 1 argument".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let prefix = arg_string(vm, &args[0], "starts_with")?;
    Ok(Value::bool(s.starts_with(&prefix)))
}

fn method_ends_with(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "ends_with() takes exactly 1 argument".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let suffix = arg_string(vm, &args[0], "ends_with")?;
    Ok(Value::bool(s.ends_with(&suffix)))
}

fn method_contains(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "contains() takes exactly 1 argument".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let substr = arg_string(vm, &args[0], "contains")?;
    Ok(Value::bool(s.contains(&substr)))
}

fn method_split(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "split() takes exactly 1 argument".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let delim = arg_string(vm, &args[0], "split")?;

    vm.heap.lock_gc();
    let mut parts: Vec<Value> = Vec::new();
    for part in s.split(&delim) {
        let h = vm.heap.alloc_string(part.to_string())?;
        parts.push(Value::string(h));
    }
    let list_h = vm.heap.alloc_list(parts)?;
    vm.heap.unlock_gc();

    Ok(Value::list(list_h))
}

fn method_trim(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = get_string(vm, receiver)?;
    let trimmed = s.trim().to_string();
    let h = vm.heap.alloc_string(trimmed)?;
    Ok(Value::string(h))
}

fn method_replace(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "replace() takes exactly 2 arguments".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let search = arg_string(vm, &args[0], "replace")?;
    let repl = arg_string(vm, &args[1], "replace")?;
    let result = s.replace(&search, &repl);
    let h = vm.heap.alloc_string(result)?;
    Ok(Value::string(h))
}

fn method_to_upper(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = get_string(vm, receiver)?;
    let h = vm.heap.alloc_string(s.to_uppercase())?;
    Ok(Value::string(h))
}

fn method_to_lower(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = get_string(vm, receiver)?;
    let h = vm.heap.alloc_string(s.to_lowercase())?;
    Ok(Value::string(h))
}

fn method_chars(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let s = get_string(vm, receiver)?;

    vm.heap.lock_gc();
    let mut char_vals: Vec<Value> = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let h = vm.heap.alloc_string(ch.to_string())?;
        char_vals.push(Value::string(h));
    }
    let list_h = vm.heap.alloc_list(char_vals)?;
    vm.heap.unlock_gc();

    Ok(Value::list(list_h))
}

fn method_index_of(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "index_of() takes exactly 1 argument".into(),
        ));
    }
    let haystack = get_string(vm, receiver)?;
    let needle = arg_string(vm, &args[0], "index_of")?;
    let result = match haystack.find(&needle) {
        Some(byte_pos) => haystack[..byte_pos].chars().count() as i64,
        None => -1,
    };
    Ok(Value::int(result))
}

fn method_substring(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "substring() takes exactly 2 arguments".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let start = args[0].as_int().ok_or(RuntimeError::TypeMismatch(
        "substring: start must be an integer".into(),
    ))? as usize;
    let end = args[1].as_int().ok_or(RuntimeError::TypeMismatch(
        "substring: end must be an integer".into(),
    ))? as usize;

    let char_count = s.chars().count();
    let start = start.min(char_count);
    let end = end.min(char_count);
    let result: String = if start <= end {
        s.chars().skip(start).take(end - start).collect()
    } else {
        String::new()
    };

    let h = vm.heap.alloc_string(result)?;
    Ok(Value::string(h))
}

fn method_repeat(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "repeat() takes exactly 1 argument".into(),
        ));
    }
    let s = get_string(vm, receiver)?;
    let n = args[0]
        .as_int()
        .ok_or_else(|| RuntimeError::TypeMismatch("repeat: argument must be an Int".into()))?;
    if n < 0 {
        return Err(RuntimeError::TypeMismatch(
            "repeat: count must be non-negative".into(),
        ));
    }
    let total_len = s.len().saturating_mul(n as usize);
    if total_len > 10_000_000 {
        return Err(RuntimeError::SystemError(
            "repeat() result exceeds 10MB limit".into(),
        ));
    }
    let result = s.repeat(n as usize);
    let h = vm.heap.alloc_string(result)?;
    Ok(Value::string(h))
}

fn method_to_string(_vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    // A string's to_string() returns itself.
    Ok(receiver)
}
