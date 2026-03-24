//! Extended string natives: join.
//! (starts_with, ends_with, contains, repeat moved to String methods in beta.13)

use ach_macros::{ach_module, ach_native};
use memory::Value;
use vm::error::RuntimeError;
use vm::machine::VM;

#[ach_module(name = "string_ext")]
pub mod string_ext_impl {
    use super::*;

    /// `join(list, separator)` → String — joins a list of strings.
    #[ach_native(name = "join", arity = 2)]
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

        if !args[1].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "join() second argument must be a String".into(),
            ));
        }
        let sep_handle = args[1]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let sep = vm
            .heap
            .get_string(sep_handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?
            .clone();

        let list = vm
            .heap
            .get_list(list_handle)
            .ok_or(RuntimeError::SystemError("List missing".into()))?
            .clone();

        let mut result = String::new();
        for (i, val) in list.iter().enumerate() {
            if !val.is_string() {
                return Err(RuntimeError::TypeMismatch(
                    "join() list must contain only Strings".into(),
                ));
            }
            if i > 0 {
                result.push_str(&sep);
            }
            let h = val
                .as_handle()
                .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
            let s = vm
                .heap
                .get_string(h)
                .ok_or(RuntimeError::SystemError("String missing".into()))?;
            result.push_str(s);
        }
        let handle = vm.heap.alloc_string(result)?;
        Ok(Value::string(handle))
    }
}
