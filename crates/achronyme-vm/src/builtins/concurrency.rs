//! Concurrency built-ins (Channels)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::{shared, Arc};
use achronyme_types::value::VmFuture;
use tokio::sync::mpsc;

/// channel() -> [Sender, Receiver]
/// Creates an unbounded mpsc channel.
pub fn vm_channel(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime(
            "channel() expects 0 arguments".to_string(),
        ));
    }

    let (tx, rx) = mpsc::unbounded_channel();

    let sender = Value::Sender(Arc::new(tx));
    let receiver = Value::Receiver(Arc::new(tokio::sync::Mutex::new(rx)));

    // Return as a vector [sender, receiver]
    let vec = vec![sender, receiver];
    Ok(Value::Vector(shared(vec)))
}

// === Sender Methods ===

/// Sender.send(value) -> Future<Null>
pub fn vm_sender_send(_vm: &VM, sender_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "send() expects 1 argument (value), got {}",
            args.len()
        )));
    }

    let message = args[0].clone();

    match sender_val {
        Value::Sender(tx_arc) => {
            // We just send immediately for unbounded channel
            // UnboundedSender is thread-safe and we can clone it from Arc
            let tx = (**tx_arc).clone();

            // We return a Future to allow 'await tx.send(val)' in the script
            // This maintains consistency and allows future switch to bounded channels (which need await)
            let future = async move {
                match tx.send(message) {
                    Ok(_) => Value::Null,
                    Err(e) => Value::Error {
                        message: format!("Channel closed: {}", e),
                        kind: Some("ChannelError".into()),
                        source: None,
                    },
                }
            };

            Ok(Value::Future(VmFuture::new(future)))
        }
        _ => Err(VmError::TypeError {
            operation: "send".to_string(),
            expected: "Sender".to_string(),
            got: format!("{:?}", sender_val),
        }),
    }
}

// === Receiver Methods ===

/// Receiver.recv() -> Future<Value>
/// Returns value or null if closed
pub fn vm_receiver_recv(
    _vm: &VM,
    receiver_val: &Value,
    args: &[Value],
) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime(format!(
            "recv() expects 0 arguments, got {}",
            args.len()
        )));
    }

    match receiver_val {
        Value::Receiver(rx_arc) => {
            let rx_arc = rx_arc.clone();

            let future = async move {
                // Lock the receiver mutex
                let mut rx = rx_arc.lock().await;
                match rx.recv().await {
                    Some(val) => val,
                    None => Value::Null, // Channel closed
                }
            };

            Ok(Value::Future(VmFuture::new(future)))
        }
        _ => Err(VmError::TypeError {
            operation: "recv".to_string(),
            expected: "Receiver".to_string(),
            got: format!("{:?}", receiver_val),
        }),
    }
}

// === AsyncMutex Methods ===

/// AsyncMutex(initial_value) -> AsyncMutex
pub fn vm_mutex(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(
            "AsyncMutex() expects 1 argument (initial value)".to_string(),
        ));
    }

    let initial_value = args[0].clone();
    let mutex = tokio::sync::Mutex::new(initial_value);
    Ok(Value::AsyncMutex(std::sync::Arc::new(mutex)))
}

/// AsyncMutex.lock() -> Future<MutexGuard>
pub fn vm_mutex_lock(_vm: &VM, mutex_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("lock() expects 0 arguments".to_string()));
    }

    match mutex_val {
        Value::AsyncMutex(mutex_arc) => {
            let mutex_arc = mutex_arc.clone();

            let future = async move {
                // lock_owned() returns an OwnedMutexGuard which we can store
                let guard = mutex_arc.lock_owned().await;
                Value::MutexGuard(shared(guard))
            };

            Ok(Value::Future(VmFuture::new(future)))
        }
        _ => Err(VmError::TypeError {
            operation: "lock".to_string(),
            expected: "AsyncMutex".to_string(),
            got: format!("{:?}", mutex_val),
        }),
    }
}

// === MutexGuard Methods ===

/// MutexGuard.get() -> Value
pub fn vm_guard_get(_vm: &VM, guard_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("get() expects 0 arguments".to_string()));
    }

    match guard_val {
        Value::MutexGuard(guard_rc) => {
            let guard = guard_rc.read();
            Ok(guard.clone()) // Clone the inner value (derefs Guard -> Value)
        }
        _ => Err(VmError::TypeError {
            operation: "get".to_string(),
            expected: "MutexGuard".to_string(),
            got: format!("{:?}", guard_val),
        }),
    }
}

/// MutexGuard.set(value) -> Null
pub fn vm_guard_set(_vm: &VM, guard_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("set() expects 1 argument".to_string()));
    }

    let new_value = args[0].clone();

    match guard_val {
        Value::MutexGuard(guard_rc) => {
            let mut guard = guard_rc.write();
            // Dereference RwLockWriteGuard<OwnedMutexGuard> -> OwnedMutexGuard -> Value
            **guard = new_value;
            Ok(Value::Null)
        }
        _ => Err(VmError::TypeError {
            operation: "set".to_string(),
            expected: "MutexGuard".to_string(),
            got: format!("{:?}", guard_val),
        }),
    }
}
