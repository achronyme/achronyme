//! I/O natives (feature-gated): read_line, read_file, write_file.

use ach_macros::{ach_module, ach_native};
use memory::Value;
use vm::error::RuntimeError;
use vm::machine::VM;

#[ach_module(name = "io")]
pub mod io_impl {
    use super::*;

    /// `read_line()` → String from stdin (trimmed).
    #[ach_native(name = "read_line", arity = 0)]
    pub fn native_read_line(vm: &mut VM, _args: &[Value]) -> Result<Value, RuntimeError> {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| RuntimeError::IoError {
                operation: "read_line".into(),
                detail: e.to_string(),
            })?;
        let trimmed = input.trim_end_matches('\n').trim_end_matches('\r');
        let handle = vm.heap.alloc_string(trimmed.to_string())?;
        Ok(Value::string(handle))
    }

    /// `read_file(path)` → String contents of a file.
    #[ach_native(name = "read_file", arity = 1)]
    pub fn native_read_file(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::ArityMismatch(
                "read_file() takes exactly 1 argument".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "read_file() expects a String path".into(),
            ));
        }
        let handle = args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let path = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::StaleHeapHandle {
                type_name: "String",
                context: "read_file",
            })?
            .clone();

        const MAX_READ_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > MAX_READ_SIZE {
                return Err(RuntimeError::ResourceLimitExceeded(format!(
                    "read_file('{}') file too large ({} bytes, max {})",
                    path,
                    meta.len(),
                    MAX_READ_SIZE,
                )));
            }
        }
        let contents = std::fs::read_to_string(&path).map_err(|e| RuntimeError::IoError {
            operation: format!("read_file('{path}')"),
            detail: e.to_string(),
        })?;
        let h = vm.heap.alloc_string(contents)?;
        Ok(Value::string(h))
    }

    /// `write_file(path, contents)` → nil. Writes string to file.
    #[ach_native(name = "write_file", arity = 2)]
    pub fn native_write_file(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::ArityMismatch(
                "write_file() takes exactly 2 arguments".into(),
            ));
        }
        if !args[0].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "write_file() first argument must be a String path".into(),
            ));
        }
        if !args[1].is_string() {
            return Err(RuntimeError::TypeMismatch(
                "write_file() second argument must be a String".into(),
            ));
        }
        let path_handle = args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let path = vm
            .heap
            .get_string(path_handle)
            .ok_or(RuntimeError::StaleHeapHandle {
                type_name: "String",
                context: "write_file",
            })?
            .clone();

        let content_handle = args[1]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let contents = vm
            .heap
            .get_string(content_handle)
            .ok_or(RuntimeError::StaleHeapHandle {
                type_name: "String",
                context: "write_file",
            })?
            .clone();

        std::fs::write(&path, &contents).map_err(|e| RuntimeError::IoError {
            operation: format!("write_file('{path}')"),
            detail: e.to_string(),
        })?;
        Ok(Value::nil())
    }
}
