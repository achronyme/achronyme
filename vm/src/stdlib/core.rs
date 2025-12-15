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
        return Err(RuntimeError::ArityMismatch(
            "len() takes exactly 1 argument".into(),
        ));
    }
    let val = &args[0];
    if val.is_string() {
        let handle = val.as_handle().unwrap();
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::Unknown("String not found".into()))?;
        Ok(Value::number(s.len() as f64))
    } else if val.is_list() {
        let handle = val.as_handle().unwrap();
        let l = vm
            .heap
            .get_list(handle)
            .ok_or(RuntimeError::Unknown("List not found".into()))?;
        Ok(Value::number(l.len() as f64))
    } else if val.is_map() {
        // Placeholder until Map is fully exposed in Heap
        Err(RuntimeError::TypeMismatch(
            "Map length not yet supported via native".into(),
        ))
    } else {
        Err(RuntimeError::TypeMismatch("Expected String or List".into()))
    }
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
