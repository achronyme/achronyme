use crate::error::RuntimeError;
use crate::machine::VM;
use memory::{FieldElement, Value};

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
        return Err(RuntimeError::ArityMismatch("len() takes exactly 1 argument".into()));
    }
    let val = &args[0];

    if val.is_string() {
        let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm.heap.get_string(handle).ok_or(RuntimeError::SystemError("Dangling string handle".into()))?;
        Ok(Value::int(s.len() as i64))
    } else if val.is_list() {
        let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
        let l = vm.heap.get_list(handle).ok_or(RuntimeError::SystemError("Dangling list handle".into()))?;
        Ok(Value::int(l.len() as i64))
    } else if val.is_map() {
        let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad map handle".into()))?;
        let m = vm.heap.get_map(handle).ok_or(RuntimeError::SystemError("Dangling map handle".into()))?;
        Ok(Value::int(m.len() as i64))
    } else {
        Err(RuntimeError::TypeMismatch("len() expects String, List, or Map".into()))
    }
}

pub fn native_push(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch("push(list, item) takes exactly 2 arguments".into()));
    }

    let target = args[0];
    let item = args[1];

    if !target.is_list() {
        return Err(RuntimeError::TypeMismatch("First argument to push must be a List".into()));
    }

    let handle = target.as_handle().ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
    let list = vm.heap.get_list_mut(handle)
        .ok_or(RuntimeError::SystemError("List corrupted or missing".into()))?;

    list.push(item);

    Ok(Value::nil())
}

pub fn native_pop(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch("pop(list) takes exactly 1 argument".into()));
    }

    let target = args[0];
    if !target.is_list() {
        return Err(RuntimeError::TypeMismatch("Argument to pop must be a List".into()));
    }

    let handle = target.as_handle().ok_or(RuntimeError::TypeMismatch("bad list handle".into()))?;
    let list = vm.heap.get_list_mut(handle)
        .ok_or(RuntimeError::SystemError("List corrupted or missing".into()))?;

    let val = list.pop().unwrap_or(Value::nil());
    Ok(val)
}

pub fn native_keys(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch("keys(map) takes exactly 1 argument".into()));
    }

    let target = args[0];
    if !target.is_map() {
        return Err(RuntimeError::TypeMismatch("Argument to keys must be a Map".into()));
    }

    let map_handle = target.as_handle().ok_or(RuntimeError::TypeMismatch("bad map handle".into()))?;

    let keys_raw: Vec<String> = {
        let map = vm.heap.get_map(map_handle).ok_or(RuntimeError::SystemError("Map corrupted".into()))?;
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

pub fn native_field(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "field() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];

    let fe = if val.is_int() {
        FieldElement::from_i64(val.as_int().unwrap())
    } else if val.is_string() {
        let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm.heap.get_string(handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?
            .clone();
        if s.starts_with("0x") || s.starts_with("0X") {
            FieldElement::from_hex_str(&s).ok_or(RuntimeError::TypeMismatch(
                format!("Invalid hex string for field(): '{}'", s),
            ))?
        } else {
            FieldElement::from_decimal_str(&s).ok_or(RuntimeError::TypeMismatch(
                format!("Invalid decimal string for field(): '{}'", s),
            ))?
        }
    } else {
        return Err(RuntimeError::TypeMismatch(
            "field() expects Int or String".into(),
        ));
    };

    let handle = vm.heap.alloc_field(fe);
    Ok(Value::field(handle))
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
        return Err(RuntimeError::ArityMismatch("proof_json() takes exactly 1 argument".into()));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch("proof_json expects a Proof".into()));
    }
    let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm.heap.get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .proof_json.clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}

pub fn native_proof_public(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch("proof_public() takes exactly 1 argument".into()));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch("proof_public expects a Proof".into()));
    }
    let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm.heap.get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .public_json.clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}

pub fn native_proof_vkey(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch("proof_vkey() takes exactly 1 argument".into()));
    }
    let val = args[0];
    if !val.is_proof() {
        return Err(RuntimeError::TypeMismatch("proof_vkey expects a Proof".into()));
    }
    let handle = val.as_handle().ok_or(RuntimeError::TypeMismatch("bad proof handle".into()))?;
    let json = vm.heap.get_proof(handle)
        .ok_or(RuntimeError::SystemError("proof not found".into()))?
        .vkey_json.clone();
    let s = vm.heap.alloc_string(json);
    Ok(Value::string(s))
}
