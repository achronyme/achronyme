use crate::error::RuntimeError;
use crate::machine::VM;
use ach_macros::{ach_module, ach_native};
use memory::Value;

#[ach_module(name = "string")]
pub mod string_impl {
    use super::*;

    #[ach_native(name = "substring", arity = 3)]
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
            .ok_or(RuntimeError::TypeMismatch("end must be an integer".into()))?
            as usize;

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

    #[ach_native(name = "index_of", arity = 2)]
    pub fn native_index_of(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::ArityMismatch(
                "index_of(str, substr) takes exactly 2 arguments".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "First argument to index_of must be a String".into(),
            ));
        }
        if !args[1].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "Second argument to index_of must be a String".into(),
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

    #[ach_native(name = "split", arity = 2)]
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

        vm.heap.lock_gc();
        let parts: Vec<Value> = s
            .split(&delim)
            .map(|part| {
                let h = vm.heap.alloc_string(part.to_string());
                Value::string(h)
            })
            .collect();
        let list_h = vm.heap.alloc_list(parts);
        vm.heap.unlock_gc();

        Ok(Value::list(list_h))
    }

    #[ach_native(name = "trim", arity = 1)]
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

    #[ach_native(name = "replace", arity = 3)]
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

    #[ach_native(name = "to_upper", arity = 1)]
    pub fn native_to_upper(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::ArityMismatch(
                "to_upper(str) takes exactly 1 argument".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "Argument to to_upper must be a String".into(),
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

    #[ach_native(name = "to_lower", arity = 1)]
    pub fn native_to_lower(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::ArityMismatch(
                "to_lower(str) takes exactly 1 argument".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "Argument to to_lower must be a String".into(),
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

    #[ach_native(name = "chars", arity = 1)]
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

        vm.heap.lock_gc();
        let char_vals: Vec<Value> = s
            .chars()
            .map(|ch| {
                let h = vm.heap.alloc_string(ch.to_string());
                Value::string(h)
            })
            .collect();
        let list_h = vm.heap.alloc_list(char_vals);
        vm.heap.unlock_gc();

        Ok(Value::list(list_h))
    }
}
