//! Type conversion natives: parse_int.
//! (to_string, to_field, to_int moved to methods in beta.13)

use ach_macros::{ach_module, ach_native};
use akron::error::RuntimeError;
use akron::machine::VM;
use memory::Value;

#[ach_module(name = "conv")]
pub mod conv_impl {
    use super::*;

    /// `parse_int(str)` → Int parsed from string, or error.
    #[ach_native(name = "parse_int", arity = 1)]
    pub fn native_parse_int(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "parse_int() takes exactly 1 argument",
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::type_mismatch("parse_int() expects a String"));
        }
        let handle = args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::type_mismatch("bad string handle"))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::stale_heap("String", "parse_int"))?;
        let n: i64 = s
            .trim()
            .parse()
            .map_err(|_| RuntimeError::type_mismatch(format!("Cannot parse '{}' as integer", s)))?;
        Ok(Value::int(n))
    }
}
