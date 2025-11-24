//! Async built-in functions

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::value::VmFuture;
use std::time::Duration;

/// sleep(ms) -> Future
pub fn vm_sleep(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "sleep() expects 1 argument, got {}",
            args.len()
        )));
    }

    let ms = match args[0] {
        Value::Number(n) => n,
        _ => {
            return Err(VmError::TypeError {
                operation: "sleep".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    if ms < 0.0 {
        return Err(VmError::Runtime(
            "sleep() duration cannot be negative".to_string(),
        ));
    }

    let duration = Duration::from_millis(ms as u64);

    // Create a future that sleeps and returns Null
    let future = async move {
        tokio::time::sleep(duration).await;
        Value::Null
    };

    Ok(Value::Future(VmFuture::new(future)))
}
