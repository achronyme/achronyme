//! Type conversion natives: parse_int.
//! (to_string, to_field, to_int moved to methods in beta.13)

use ach_macros::{ach_module, ach_native};
use memory::Value;
use vm::error::RuntimeError;
use vm::machine::VM;

#[ach_module(name = "conv")]
pub mod conv_impl {
    use super::*;

    /// `parse_int(str)` → Int parsed from string, or error.
    #[ach_native(name = "parse_int", arity = 1)]
    pub fn native_parse_int(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::ArityMismatch(
                "parse_int() takes exactly 1 argument".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "parse_int() expects a String".into(),
            ));
        }
        let handle = args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?;
        let n: i64 = s
            .trim()
            .parse()
            .map_err(|_| RuntimeError::TypeMismatch(format!("Cannot parse '{}' as integer", s)))?;
        Ok(Value::int(n))
    }
}
