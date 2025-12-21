use crate::error::RuntimeError;
use crate::machine::VM;
use memory::Value;

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
    
    // [STANDARD]: Polymorphic dispatch based on tags
    if val.is_string() {
        let handle = val.as_handle().unwrap(); // Safe: guarded by is_string()
        let s = vm.heap.get_string(handle).ok_or(RuntimeError::SystemError("Dangling string handle".into()))?;
        Ok(Value::number(s.len() as f64))
    } else if val.is_list() {
        let handle = val.as_handle().unwrap();
        let l = vm.heap.get_list(handle).ok_or(RuntimeError::SystemError("Dangling list handle".into()))?;
        Ok(Value::number(l.len() as f64))
    } else if val.is_map() {
        let handle = val.as_handle().unwrap();
        let m = vm.heap.get_map(handle).ok_or(RuntimeError::SystemError("Dangling map handle".into()))?;
        Ok(Value::number(m.len() as f64))
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

    let handle = target.as_handle().unwrap();
    // [STANDARD]: Mutable access required. Fails cleanly if handle is invalid.
    let list = vm.heap.get_list_mut(handle)
        .ok_or(RuntimeError::SystemError("List corrupted or missing".into()))?;
    
    list.push(item);
    
    Ok(Value::nil()) // Void return
}

pub fn native_pop(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch("pop(list) takes exactly 1 argument".into()));
    }

    let target = args[0];
    if !target.is_list() {
        return Err(RuntimeError::TypeMismatch("Argument to pop must be a List".into()));
    }

    let handle = target.as_handle().unwrap();
    let list = vm.heap.get_list_mut(handle)
        .ok_or(RuntimeError::SystemError("List corrupted or missing".into()))?;

    // [STANDARD]: Safe handling of empty lists (returns Nil, implies Option-like behavior)
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

    let map_handle = target.as_handle().unwrap();

    // [CRITICAL]: Scope Limiting for Borrow Checker Compliance
    // Step 1: Read keys (Immutable Borrow). Copy to temp vector.
    let keys_raw: Vec<String> = {
        let map = vm.heap.get_map(map_handle).ok_or(RuntimeError::SystemError("Map corrupted".into()))?;
        map.keys().cloned().collect() // Clone strings to own them
    }; 
    // Scope ends here. Immutable borrow dropped.

    // Step 2: Allocate strings (Mutable Borrow of Heap).
    let mut key_values = Vec::with_capacity(keys_raw.len());
    for k in keys_raw {
        let handle = vm.heap.alloc_string(k);
        key_values.push(Value::string(handle));
    }

    // Step 3: Allocate list (Mutable Borrow of Heap).
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
    let type_name = if val.is_number() {
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
    } else if val.is_function() {
        "Function"
    }
    // Script function
    else if val.is_native() {
        "Native"
    } else if val.is_complex() {
        "Complex"
    } else {
        "Unknown"
    };

    // Intern/Alloc the string
    let s = type_name.to_string();
    // We need to use VM logic to intern/alloc.
    // Similar logic to define_native, but returning a Value.
    // VM doesn't expose a simple "create_string_value" public method that does interning + alloc?
    // We can use heap.alloc_string directly.
    let handle = vm.heap.alloc_string(s);
    // Note: We are not interning this in vm.interner because it's a runtime value, not a global name.

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
    Ok(Value::number(duration.as_secs_f64()))
}
