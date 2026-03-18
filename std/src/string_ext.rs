//! Extended string natives: starts_with, ends_with, contains, join, repeat.

use memory::Value;
use vm::error::RuntimeError;
use vm::machine::VM;
use vm::module::{NativeDef, NativeModule};

pub struct StringExtModule;

impl NativeModule for StringExtModule {
    fn name(&self) -> &'static str {
        "string_ext"
    }

    fn natives(&self) -> Vec<NativeDef> {
        vec![
            NativeDef {
                name: "starts_with",
                func: native_starts_with,
                arity: 2,
            },
            NativeDef {
                name: "ends_with",
                func: native_ends_with,
                arity: 2,
            },
            NativeDef {
                name: "contains",
                func: native_contains,
                arity: 2,
            },
            NativeDef {
                name: "join",
                func: native_join,
                arity: 2,
            },
            NativeDef {
                name: "repeat",
                func: native_repeat,
                arity: 2,
            },
        ]
    }
}

/// Helper: extract a String from a Value.
fn extract_string<'a>(vm: &'a VM, val: &Value, fn_name: &str) -> Result<&'a str, RuntimeError> {
    if !val.is_string() {
        return Err(RuntimeError::TypeMismatch(format!(
            "{fn_name}() expects a String argument"
        )));
    }
    let handle = val
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
    vm.heap
        .get_string(handle)
        .map(|s| s.as_str())
        .ok_or(RuntimeError::SystemError("String missing".into()))
}

/// `starts_with(str, prefix)` → Bool
pub fn native_starts_with(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "starts_with() takes exactly 2 arguments".into(),
        ));
    }
    let s = extract_string(vm, &args[0], "starts_with")?.to_string();
    let prefix = extract_string(vm, &args[1], "starts_with")?;
    Ok(Value::bool(s.starts_with(prefix)))
}

/// `ends_with(str, suffix)` → Bool
pub fn native_ends_with(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "ends_with() takes exactly 2 arguments".into(),
        ));
    }
    let s = extract_string(vm, &args[0], "ends_with")?.to_string();
    let suffix = extract_string(vm, &args[1], "ends_with")?;
    Ok(Value::bool(s.ends_with(suffix)))
}

/// `contains(str, substr)` → Bool
pub fn native_contains(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "contains() takes exactly 2 arguments".into(),
        ));
    }
    let s = extract_string(vm, &args[0], "contains")?.to_string();
    let substr = extract_string(vm, &args[1], "contains")?;
    Ok(Value::bool(s.contains(substr)))
}

/// `join(list, separator)` → String — joins a list of strings.
pub fn native_join(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "join() takes exactly 2 arguments".into(),
        ));
    }
    if !args[0].is_list() {
        return Err(RuntimeError::TypeMismatch(
            "join() first argument must be a List".into(),
        ));
    }
    let list_handle = args[0]
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad list handle".into()))?;
    let sep = extract_string(vm, &args[1], "join")?.to_string();

    let list = vm
        .heap
        .get_list(list_handle)
        .ok_or(RuntimeError::SystemError("List missing".into()))?
        .clone();

    let mut parts = Vec::with_capacity(list.len());
    for val in &list {
        if !val.is_string() {
            return Err(RuntimeError::TypeMismatch(
                "join() list must contain only Strings".into(),
            ));
        }
        let h = val
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(h)
            .ok_or(RuntimeError::SystemError("String missing".into()))?;
        parts.push(s.clone());
    }

    let result = parts.join(&sep);
    let handle = vm.heap.alloc_string(result);
    Ok(Value::string(handle))
}

/// `repeat(str, n)` → String repeated n times.
pub fn native_repeat(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "repeat() takes exactly 2 arguments".into(),
        ));
    }
    let s = extract_string(vm, &args[0], "repeat")?.to_string();
    let n = args[1].as_int().ok_or_else(|| {
        RuntimeError::TypeMismatch("repeat() second argument must be an Int".into())
    })?;
    if n < 0 {
        return Err(RuntimeError::TypeMismatch(
            "repeat() count must be non-negative".into(),
        ));
    }
    let result = s.repeat(n as usize);
    let handle = vm.heap.alloc_string(result);
    Ok(Value::string(handle))
}
