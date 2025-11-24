//! Async built-in functions

use crate::bytecode::Closure;
use crate::error::VmError;
use crate::value::Value;
use crate::vm::{CallFrame, VM};
use achronyme_types::function::Function;
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

/// spawn(func, ...args) -> Future
/// Spawns a new task running the given function.
pub fn vm_spawn(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "spawn() expects at least 1 argument".to_string(),
        ));
    }

    let func = args[0].clone();
    let func_args = args[1..].to_vec();

    // Create child VM
    let mut child_vm = vm.new_child();

    // Set up call frame in child VM
    match &func {
        Value::Function(Function::VmClosure(closure_any)) => {
            let closure = closure_any
                .downcast_ref::<Closure>()
                .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

            // Create frame
            let mut new_frame = CallFrame::new(closure.prototype.clone(), None);
            new_frame.upvalues = closure.upvalues.clone();

            // Copy arguments
            for (i, arg) in func_args.iter().enumerate() {
                if i >= 256 {
                    return Err(VmError::Runtime("Too many arguments (max 256)".into()));
                }
                new_frame.registers.set(i as u8, arg.clone())?;
            }

            child_vm.frames.push(new_frame);
        }
        _ => {
            return Err(VmError::TypeError {
                operation: "spawn".to_string(),
                expected: "Function".to_string(),
                got: format!("{:?}", func),
            })
        }
    }

    // Spawn future on local set
    // The future runs the VM and returns the result
    let future = async move { child_vm.run().await };

    // We use spawn_local because Value is !Send (Rc)
    let handle = tokio::task::spawn_local(future);

    // Wrap the handle in a VmFuture so it can be awaited in Achronyme
    let vm_future = async move {
        match handle.await {
            Ok(Ok(v)) => v, // Task succeeded and VM returned Value
            Ok(Err(e)) => Value::Error {
                // Task succeeded but VM returned Error
                message: e.to_string(),
                kind: Some("RuntimeError".into()),
                source: None,
            },
            Err(e) => Value::Error {
                // Task failed (panic/cancellation)
                message: format!("Task execution error: {}", e),
                kind: Some("TaskError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(vm_future)))
}

/// read_file(path) -> Future
/// Asynchronously reads a file and returns its content as a string.
pub fn vm_read_file(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "read_file() expects 1 argument, got {}",
            args.len()
        )));
    }

    let path = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "read_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let future = async move {
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => Value::String(content),
            Err(e) => Value::Error {
                message: format!("Failed to read file '{}': {}", path, e),
                kind: Some("IOError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

/// write_file(path, content) -> Future
/// Asynchronously writes content to a file (overwriting).
pub fn vm_write_file(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "write_file() expects 2 arguments, got {}",
            args.len()
        )));
    }

    let path = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "write_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let content = match &args[1] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "write_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let future = async move {
        match tokio::fs::write(&path, content).await {
            Ok(_) => Value::Null,
            Err(e) => Value::Error {
                message: format!("Failed to write file '{}': {}", path, e),
                kind: Some("IOError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

/// append_file(path, content) -> Future
/// Asynchronously appends content to a file.
pub fn vm_append_file(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "append_file() expects 2 arguments, got {}",
            args.len()
        )));
    }

    let path = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "append_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let content = match &args[1] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "append_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let future = async move {
        use tokio::io::AsyncWriteExt;
        let result = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await?;
            file.write_all(content.as_bytes()).await?;
            Ok::<(), std::io::Error>(())
        }
        .await;

        match result {
            Ok(_) => Value::Null,
            Err(e) => Value::Error {
                message: format!("Failed to append to file '{}': {}", path, e),
                kind: Some("IOError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

/// delete_file(path) -> Future
/// Asynchronously deletes a file.
pub fn vm_delete_file(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "delete_file() expects 1 argument, got {}",
            args.len()
        )));
    }

    let path = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "delete_file".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let future = async move {
        match tokio::fs::remove_file(&path).await {
            Ok(_) => Value::Boolean(true),
            Err(e) => Value::Error {
                message: format!("Failed to delete file '{}': {}", path, e),
                kind: Some("IOError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

/// exists(path) -> Future
/// Asynchronously checks if a file exists.
pub fn vm_exists(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "exists() expects 1 argument, got {}",
            args.len()
        )));
    }

    let path = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "exists".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let future = async move {
        match tokio::fs::metadata(&path).await {
            Ok(_) => Value::Boolean(true),
            Err(_) => Value::Boolean(false),
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}
