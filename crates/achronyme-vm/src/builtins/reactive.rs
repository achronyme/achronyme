//! Reactive system built-ins (Signals, Effects)
//!
//! This module uses VM-based tracking context instead of thread-local storage
//! to support multi-threaded scenarios (e.g., spawned async tasks modifying signals).

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::{shared, Arc, Shared};
use achronyme_types::value::{EffectState, SignalState};
use std::cell::RefCell;

// Thread-local callback for legacy GUI notification (kept for backwards compatibility)
thread_local! {
    // Callback to notify external systems (like GUI) when a signal changes
    static SIGNAL_NOTIFIER: RefCell<Option<Box<dyn Fn()>>> = RefCell::new(None);
}

/// Registers a callback to be invoked whenever ANY signal changes value.
/// Used by the GUI engine to trigger rebuilds.
pub fn register_signal_notifier<F>(callback: F)
where
    F: Fn() + 'static,
{
    SIGNAL_NOTIFIER.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(callback));
    });
}

/// Notify external systems (e.g., GUI) that a signal has changed.
/// This is called when GUI widgets update signal values from user interaction.
/// Unlike set_signal_value(), this does NOT run effects (those are handled by the VM).
pub fn notify_signal_changed(_signal_rc: &Shared<SignalState>) {
    SIGNAL_NOTIFIER.with(|cell| {
        if let Some(callback) = cell.borrow().as_ref() {
            callback();
        }
    });
}

/// signal(initial_value) -> Signal
/// Creates a new reactive signal.
pub fn vm_signal(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    let initial_value = if args.is_empty() {
        Value::Null
    } else {
        args[0].clone()
    };

    let state = SignalState {
        value: initial_value,
        subscribers: Vec::new(),
    };

    Ok(Value::Signal(shared(state)))
}

/// effect(callback) -> Null
/// Registers a side effect that runs immediately and re-runs when dependencies change.
pub fn vm_effect(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(
            "effect() expects 1 argument (callback function)".to_string(),
        ));
    }

    let callback = args[0].clone();

    // Create effect state
    let effect_state = shared(EffectState {
        callback: callback.clone(),
        dependencies: Vec::new(),
    });

    // Keep effect alive by adding to VM roots
    vm.state.write().active_effects.push(effect_state.clone());

    // Run the effect immediately to track dependencies
    run_effect(vm, effect_state)?;

    Ok(Value::Null)
}

/// Helper to run an effect and track dependencies
/// Uses VM-based tracking context to support multi-threaded execution (e.g., spawned tasks)
fn run_effect(vm: &VM, effect: Shared<EffectState>) -> Result<(), VmError> {
    // 1. Cleanup: Unsubscribe from previous dependencies
    cleanup_effect(&effect);

    // 2. Set tracking context in VM (thread-safe, works across spawned tasks)
    vm.set_tracking_effect(Some(effect.clone()));

    // 3. Execute the callback
    let callback = effect.read().callback.clone();
    let result = vm.call_value(&callback, &[]);

    // 4. Clear tracking context
    vm.set_tracking_effect(None);

    // Propagate error if execution failed
    result.map(|_| ())
}

/// Unsubscribe effect from all its dependencies
fn cleanup_effect(effect_rc: &Shared<EffectState>) {
    let mut effect = effect_rc.write();

    for dep_signal in &effect.dependencies {
        // Remove this effect from the signal's subscribers
        let mut signal = dep_signal.write();
        signal.subscribers.retain(|sub_weak| {
            // Keep only if it doesn't point to us
            match sub_weak.upgrade() {
                Some(sub_rc) => !Arc::ptr_eq(&sub_rc, effect_rc),
                None => false, // Remove dead subscribers anyway
            }
        });
    }

    // Clear dependencies list
    effect.dependencies.clear();
}

// === Signal Methods ===

/// Signal.value -> Value (Getter)
/// Uses VM-based tracking context to support multi-threaded execution (e.g., spawned tasks)
pub fn vm_signal_get(vm: &VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("get() expects 0 arguments".to_string()));
    }

    match signal_val {
        Value::Signal(state_rc) => {
            let mut state = state_rc.write();

            // Track dependency if inside an effect (using VM-based context, thread-safe)
            if let Some(current_effect) = vm.get_tracking_effect() {
                // Subscribe current effect to this signal (Weak ref)
                let weak_effect = Arc::downgrade(&current_effect);
                state.subscribers.push(weak_effect);

                // Add signal to effect's dependencies (Strong ref)
                // run_effect drops the tracking_effect lock before call_value,
                // so effect is NOT locked when running callback. Safe to write lock.
                let mut effect = current_effect.write();

                // Store dependency if not already there (avoid dupes in same run)
                if let Value::Signal(original_rc) = signal_val {
                    let already_dep = effect
                        .dependencies
                        .iter()
                        .any(|d| Arc::ptr_eq(d, original_rc));
                    if !already_dep {
                        effect.dependencies.push(original_rc.clone());
                    }
                }
            }

            Ok(state.value.clone())
        }
        _ => Err(VmError::TypeError {
            operation: "get".to_string(),
            expected: "Signal".to_string(),
            got: format!("{:?}", signal_val),
        }),
    }
}

/// Signal.peek() -> Value
/// Returns the current value WITHOUT tracking dependency.
pub fn vm_signal_peek(_vm: &VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("peek() expects 0 arguments".to_string()));
    }

    match signal_val {
        Value::Signal(state_rc) => {
            let state = state_rc.read();
            Ok(state.value.clone())
        }
        _ => Err(VmError::TypeError {
            operation: "peek".to_string(),
            expected: "Signal".to_string(),
            got: format!("{:?}", signal_val),
        }),
    }
}

/// Internal helper to set signal value and trigger effects
pub fn set_signal_value(
    vm: &VM,
    signal_rc: &Shared<SignalState>,
    new_value: Value,
) -> Result<(), VmError> {
    let mut state = signal_rc.write();

    // Only update if value changed
    if state.value != new_value {
        state.value = new_value;

        // Notify subscribers
        // Clone the list of subscribers to release the lock on state
        let subscribers = state.subscribers.clone();

        drop(state); // Release lock

        // Run effects
        for weak_sub in subscribers {
            if let Some(effect_rc) = weak_sub.upgrade() {
                run_effect(vm, effect_rc)?;
            }
        }

        // Notify external listener (e.g. GUI) via thread-local (legacy)
        SIGNAL_NOTIFIER.with(|cell| {
            if let Some(callback) = cell.borrow().as_ref() {
                callback();
            }
        });

        // Notify via VM-based notifier (preferred for render engine)
        vm.notify_signal_change();
    }
    Ok(())
}

/// Signal.set(new_value) -> Null
pub fn vm_signal_set(vm: &VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("set() expects 1 argument".to_string()));
    }

    let new_value = args[0].clone();

    match signal_val {
        Value::Signal(state_rc) => {
            set_signal_value(vm, state_rc, new_value)?;
            Ok(Value::Null)
        }
        _ => Err(VmError::TypeError {
            operation: "set".to_string(),
            expected: "Signal".to_string(),
            got: format!("{:?}", signal_val),
        }),
    }
}
