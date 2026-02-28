use crate::error::RuntimeError;
use crate::machine::VM;
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use memory::{FieldElement, Value};

/// Extract a FieldElement from a VM Value (Int or Field).
fn extract_fe(vm: &VM, val: &Value) -> Result<FieldElement, RuntimeError> {
    if val.is_field() {
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::TypeMismatch("bad field handle".into()))?;
        let fe = vm
            .heap
            .get_field(handle)
            .ok_or(RuntimeError::SystemError("Field missing".into()))?;
        Ok(*fe)
    } else if val.is_int() {
        let i = val
            .as_int()
            .ok_or(RuntimeError::TypeMismatch("bad int value".into()))?;
        Ok(FieldElement::from_i64(i))
    } else {
        Err(RuntimeError::TypeMismatch(
            "Expected Int or Field value".into(),
        ))
    }
}

pub fn native_print(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{}", vm.val_to_string(arg));
    }
    println!();
    Ok(Value::nil())
}

pub fn native_len(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "len() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];

    if val.is_string() {
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::SystemError("Dangling string handle".into()))?;
        Ok(Value::int(s.chars().count() as i64))
    } else if val.is_list() {
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
        let l = vm
            .heap
            .get_list(handle)
            .ok_or(RuntimeError::SystemError("Dangling list handle".into()))?;
        Ok(Value::int(l.len() as i64))
    } else if val.is_map() {
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::TypeMismatch("bad map handle".into()))?;
        let m = vm
            .heap
            .get_map(handle)
            .ok_or(RuntimeError::SystemError("Dangling map handle".into()))?;
        Ok(Value::int(m.len() as i64))
    } else {
        Err(RuntimeError::TypeMismatch(
            "len() expects String, List, or Map".into(),
        ))
    }
}

pub fn native_push(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "push(list, item) takes exactly 2 arguments".into(),
        ));
    }

    let target = args[0];
    let item = args[1];

    if !target.is_list() {
        return Err(RuntimeError::TypeMismatch(
            "First argument to push must be a List".into(),
        ));
    }

    let handle = target
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
    let list = vm
        .heap
        .get_list_mut(handle)
        .ok_or(RuntimeError::SystemError(
            "List corrupted or missing".into(),
        ))?;

    list.push(item);

    Ok(Value::nil())
}

pub fn native_pop(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "pop(list) takes exactly 1 argument".into(),
        ));
    }

    let target = args[0];
    if !target.is_list() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to pop must be a List".into(),
        ));
    }

    let handle = target
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
    let list = vm
        .heap
        .get_list_mut(handle)
        .ok_or(RuntimeError::SystemError(
            "List corrupted or missing".into(),
        ))?;

    let val = list.pop().unwrap_or(Value::nil());
    Ok(val)
}

pub fn native_keys(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "keys(map) takes exactly 1 argument".into(),
        ));
    }

    let target = args[0];
    if !target.is_map() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to keys must be a Map".into(),
        ));
    }

    let map_handle = target
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad map handle".into()))?;

    let keys_raw: Vec<String> = {
        let map = vm
            .heap
            .get_map(map_handle)
            .ok_or(RuntimeError::SystemError("Map corrupted".into()))?;
        map.keys().cloned().collect()
    };

    let mut key_values = Vec::with_capacity(keys_raw.len());
    for k in keys_raw {
        let handle = vm.heap.alloc_string(k);
        key_values.push(Value::string(handle));
    }

    let list_handle = vm.heap.alloc_list(key_values);

    Ok(Value::list(list_handle))
}

pub fn native_typeof(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "typeof() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];
    let type_name = if val.is_int() {
        "Number"
    } else if val.is_string() {
        "String"
    } else if val.is_bool() {
        "Bool"
    } else if val.is_nil() {
        "Nil"
    } else if val.is_list() {
        "List"
    } else if val.is_map() {
        "Map"
    } else if val.is_field() {
        "Field"
    } else if val.is_proof() {
        "Proof"
    } else if val.is_function() || val.is_closure() {
        "Function"
    } else if val.is_native() {
        "Native"
    } else {
        "Unknown"
    };

    let s = type_name.to_string();
    let handle = vm.heap.alloc_string(s);

    Ok(Value::string(handle))
}

pub fn native_assert(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "assert() takes exactly 1 argument".into(),
        ));
    }
    if !args[0].as_bool().unwrap_or(false) {
        return Err(RuntimeError::AssertionFailed);
    }
    Ok(Value::nil())
}

pub fn native_time(_vm: &mut VM, _args: &[Value]) -> Result<Value, RuntimeError> {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    Ok(Value::int(duration.as_millis() as i64))
}

pub fn native_proof_json(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "proof_json() takes exactly 1 argument".into(),
        ));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch(
            "proof_json expects a Proof".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm
        .heap
        .get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .proof_json
        .clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}

pub fn native_proof_public(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "proof_public() takes exactly 1 argument".into(),
        ));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch(
            "proof_public expects a Proof".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm
        .heap
        .get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .public_json
        .clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}

pub fn native_proof_vkey(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "proof_vkey() takes exactly 1 argument".into(),
        ));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch(
            "proof_vkey expects a Proof".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm
        .heap
        .get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .vkey_json
        .clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}

// --- String utilities ---

pub fn native_substring(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::ArityMismatch(
            "substring(str, start, end) takes exactly 3 arguments".into(),
        ));
    }
    let val = &args[0];
    if !val.is_string() {
        return Err(RuntimeError::TypeMismatch(
            "First argument to substring must be a String".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad string handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();

    let start = args[1].as_int().ok_or(RuntimeError::TypeMismatch(
        "start must be an integer".into(),
    ))? as usize;
    let end = args[2]
        .as_int()
        .ok_or(RuntimeError::TypeMismatch("end must be an integer".into()))? as usize;

    let char_count = s.chars().count();
    let start = start.min(char_count);
    let end = end.min(char_count);
    let result: String = if start <= end {
        s.chars().skip(start).take(end - start).collect()
    } else {
        String::new()
    };

    let h = vm.heap.alloc_string(result);
    Ok(Value::string(h))
}

pub fn native_index_of(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "indexOf(str, substr) takes exactly 2 arguments".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "First argument to indexOf must be a String".into(),
        ));
    }
    if !args[1].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Second argument to indexOf must be a String".into(),
        ));
    }
    let h0 = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let h1 = args[1]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let haystack = vm
        .heap
        .get_string(h0)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();
    let needle = vm
        .heap
        .get_string(h1)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();

    let result = match haystack.find(&needle) {
        Some(byte_pos) => haystack[..byte_pos].chars().count() as i64,
        None => -1,
    };
    Ok(Value::int(result))
}

pub fn native_split(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "split(str, delim) takes exactly 2 arguments".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "First argument to split must be a String".into(),
        ));
    }
    if !args[1].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Second argument to split must be a String".into(),
        ));
    }
    let h0 = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let h1 = args[1]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(h0)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();
    let delim = vm
        .heap
        .get_string(h1)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();

    let parts: Vec<Value> = s
        .split(&delim)
        .map(|part| {
            let h = vm.heap.alloc_string(part.to_string());
            Value::string(h)
        })
        .collect();

    let list_h = vm.heap.alloc_list(parts);
    Ok(Value::list(list_h))
}

pub fn native_trim(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "trim(str) takes exactly 1 argument".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to trim must be a String".into(),
        ));
    }
    let handle = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?;
    let trimmed = s.trim().to_string();
    let h = vm.heap.alloc_string(trimmed);
    Ok(Value::string(h))
}

pub fn native_replace(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::ArityMismatch(
            "replace(str, search, repl) takes exactly 3 arguments".into(),
        ));
    }
    if !args[0].is_string() || !args[1].is_string() || !args[2].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "All arguments to replace must be Strings".into(),
        ));
    }
    let h0 = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let h1 = args[1]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let h2 = args[2]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(h0)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();
    let search = vm
        .heap
        .get_string(h1)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();
    let repl = vm
        .heap
        .get_string(h2)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();

    let result = s.replace(&search, &repl);
    let h = vm.heap.alloc_string(result);
    Ok(Value::string(h))
}

pub fn native_to_upper(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "toUpper(str) takes exactly 1 argument".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to toUpper must be a String".into(),
        ));
    }
    let handle = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?;
    let upper = s.to_uppercase();
    let h = vm.heap.alloc_string(upper);
    Ok(Value::string(h))
}

pub fn native_to_lower(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "toLower(str) takes exactly 1 argument".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to toLower must be a String".into(),
        ));
    }
    let handle = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?;
    let lower = s.to_lowercase();
    let h = vm.heap.alloc_string(lower);
    Ok(Value::string(h))
}

pub fn native_chars(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "chars(str) takes exactly 1 argument".into(),
        ));
    }
    if !args[0].is_string() {
        return Err(RuntimeError::TypeMismatch(
            "Argument to chars must be a String".into(),
        ));
    }
    let handle = args[0]
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad handle".into()))?;
    let s = vm
        .heap
        .get_string(handle)
        .ok_or(RuntimeError::SystemError("String missing".into()))?
        .clone();

    let char_vals: Vec<Value> = s
        .chars()
        .map(|ch| {
            let h = vm.heap.alloc_string(ch.to_string());
            Value::string(h)
        })
        .collect();

    let list_h = vm.heap.alloc_list(char_vals);
    Ok(Value::list(list_h))
}

// --- Cryptographic natives ---

pub fn native_poseidon(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "poseidon(left, right) takes exactly 2 arguments".into(),
        ));
    }
    let left = extract_fe(vm, &args[0])?;
    let right = extract_fe(vm, &args[1])?;
    let params = PoseidonParams::bn254_t3();
    let result = poseidon_hash(&params, left, right);
    let handle = vm.heap.alloc_field(result);
    Ok(Value::field(handle))
}

pub fn native_poseidon_many(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() < 2 {
        return Err(RuntimeError::ArityMismatch(
            "poseidon_many() requires at least 2 arguments".into(),
        ));
    }
    let params = PoseidonParams::bn254_t3();
    let first = extract_fe(vm, &args[0])?;
    let second = extract_fe(vm, &args[1])?;
    let mut acc = poseidon_hash(&params, first, second);
    for arg in &args[2..] {
        let fe = extract_fe(vm, arg)?;
        acc = poseidon_hash(&params, acc, fe);
    }
    let handle = vm.heap.alloc_field(acc);
    Ok(Value::field(handle))
}

pub fn native_verify_proof(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "verify_proof(proof) takes exactly 1 argument".into(),
        ));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch(
            "verify_proof expects a Proof".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let proof_obj = vm
        .heap
        .get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .clone();

    let handler = vm.verify_handler.as_ref().ok_or(RuntimeError::SystemError(
        "verify_proof: no verify handler configured".into(),
    ))?;

    match handler.verify_proof(&proof_obj) {
        Ok(valid) => Ok(Value::bool(valid)),
        Err(msg) => Err(RuntimeError::SystemError(format!(
            "verify_proof failed: {msg}"
        ))),
    }
}
