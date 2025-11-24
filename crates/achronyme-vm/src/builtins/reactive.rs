//! Reactive system built-ins (Signals, Effects)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::value::{EffectState, SignalState};
use std::cell::RefCell;
use std::rc::Rc;

// Thread-local global tracking context
// Stores the current effect being executed, if any.
thread_local! {
    static TRACKING_CONTEXT: RefCell<Option<Rc<RefCell<EffectState>>>> = RefCell::new(None);
}

/// signal(initial_value) -> Signal
/// Creates a new reactive signal.
pub fn vm_signal(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let initial_value = if args.is_empty() {
        Value::Null
    } else {
        args[0].clone()
    };

    let state = SignalState {
        value: initial_value,
        subscribers: Vec::new(),
    };

    Ok(Value::Signal(Rc::new(RefCell::new(state))))
}

/// effect(callback) -> Null
/// Registers a side effect that runs immediately and re-runs when dependencies change.
pub fn vm_effect(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(
            "effect() expects 1 argument (callback function)".to_string(),
        ));
    }

    let callback = args[0].clone();

    // Create effect state
    let effect_state = Rc::new(RefCell::new(EffectState {
        callback: callback.clone(),
        dependencies: Vec::new(),
    }));

    // Keep effect alive by adding to VM roots
    vm.active_effects.push(effect_state.clone());

    // Run the effect immediately to track dependencies
    run_effect(vm, effect_state)?;

    Ok(Value::Null)
}

/// Helper to run an effect and track dependencies
fn run_effect(vm: &mut VM, effect: Rc<RefCell<EffectState>>) -> Result<(), VmError> {
    // 1. Cleanup: Unsubscribe from previous dependencies
    cleanup_effect(&effect);

    // 2. Set tracking context
    TRACKING_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = Some(effect.clone());
    });

    // 3. Execute the callback
    let callback = effect.borrow().callback.clone();
    let result = vm.call_value(&callback, &[]);

    // 4. Clear tracking context
    TRACKING_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = None;
    });

    // Propagate error if execution failed
    result.map(|_| ())
}

/// Unsubscribe effect from all its dependencies
fn cleanup_effect(effect_rc: &Rc<RefCell<EffectState>>) {
    let mut effect = effect_rc.borrow_mut();

    for dep_signal in &effect.dependencies {
        // Remove this effect from the signal's subscribers
        let mut signal = dep_signal.borrow_mut();
        signal.subscribers.retain(|sub_weak| {
            // Keep only if it doesn't point to us
            match sub_weak.upgrade() {
                Some(sub_rc) => !Rc::ptr_eq(&sub_rc, effect_rc),
                None => false, // Remove dead subscribers anyway
            }
        });
    }

    // Clear dependencies list
    effect.dependencies.clear();
}

// === Signal Methods ===

/// Signal.value -> Value (Getter)
pub fn vm_signal_get(_vm: &mut VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("get() expects 0 arguments".to_string()));
    }

    match signal_val {
        Value::Signal(state_rc) => {
            let mut state = state_rc.borrow_mut();

            // Track dependency if inside an effect
            TRACKING_CONTEXT.with(|ctx| {
                if let Some(current_effect) = &*ctx.borrow() {
                    // Subscribe current effect to this signal (Weak ref)
                    let weak_effect = Rc::downgrade(current_effect);
                    state.subscribers.push(weak_effect);

                    // Add signal to effect's dependencies (Strong ref)
                    // We assume vm_signal_get is called with the signal Value which contains state_rc
                    // But we have state_rc here. We need to add state_rc to effect.

                    // Note: To avoid double borrowing effect (since ctx borrows it),
                    // we need to be careful. current_effect is Rc<RefCell<EffectState>>.
                    // We can just borrow_mut() it because ctx borrows the Option, not the RefCell content directly?
                    // Actually ctx.borrow() returns Ref<Option<...>>.
                    // So we have a Ref to the Option which holds the Rc.
                    // We can clone the Rc.
                    let effect_rc = current_effect.clone();

                    // Now we can borrow_mut the effect state
                    // But wait, run_effect holds a borrow on effect?
                    // run_effect calls vm.call_value -> vm_signal_get.
                    // run_effect only borrows effect to get callback, then drops borrow.
                    // So effect is NOT borrowed when running callback. Safe to borrow_mut.

                    let mut effect = effect_rc.borrow_mut();
                    // Store dependency if not already there (avoid dupes in same run)
                    // We check ptr_eq on the Rc inside dependencies
                    // We need to clone the Signal Rc. But we only have &mut SignalState.
                    // We can't get Rc from &mut T.
                    // Solution: We need the Rc passed in signal_val.
                    if let Value::Signal(original_rc) = signal_val {
                        let already_dep = effect
                            .dependencies
                            .iter()
                            .any(|d| Rc::ptr_eq(d, original_rc));
                        if !already_dep {
                            effect.dependencies.push(original_rc.clone());
                        }
                    }
                }
            });

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
pub fn vm_signal_peek(_vm: &mut VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    if !args.is_empty() {
        return Err(VmError::Runtime("peek() expects 0 arguments".to_string()));
    }

    match signal_val {
        Value::Signal(state_rc) => {
            let state = state_rc.borrow();
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
    vm: &mut VM,
    signal_rc: &Rc<RefCell<SignalState>>,
    new_value: Value,
) -> Result<(), VmError> {
    let mut state = signal_rc.borrow_mut();

    // Only update if value changed
    if state.value != new_value {
        state.value = new_value;

        // Notify subscribers
        // Clone the list of subscribers to release the borrow on state
        let subscribers = state.subscribers.clone();

        drop(state); // Release lock

        // Run effects
        for weak_sub in subscribers {
            if let Some(effect_rc) = weak_sub.upgrade() {
                run_effect(vm, effect_rc)?;
            }
        }
    }
    Ok(())
}

/// Signal.set(new_value) -> Null
pub fn vm_signal_set(vm: &mut VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
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
