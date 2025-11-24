use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_gui::components;
use achronyme_gui::runner::{run_native, Evaluator};
use std::cell::RefCell;

// --- Thread-Local VM Access (The Architecture Fix) ---
// Instead of cloning the VM (which loses context and causes weird type errors),
// we temporarily expose the active VM to the GUI runner via a thread-local pointer.
// This allows true re-entrancy: the GUI render loop runs "inside" the VM's execution context.

thread_local! {
    static ACTIVE_VM: RefCell<Option<*mut VM>> = RefCell::new(None);
}

struct VmGuiEvaluator;

impl Evaluator for VmGuiEvaluator {
    fn call(&self, func: &Value, args: Vec<Value>) -> Result<Value, anyhow::Error> {
        ACTIVE_VM.with(|cell| {
            if let Some(vm_ptr) = *cell.borrow() {
                // SAFETY: This is safe because:
                // 1. We are single-threaded (LocalSet).
                // 2. The VM pointer is valid because `vm_gui_run` blocks while the GUI is running.
                // 3. We are re-entering the VM recursively, which `call_value` handles correctly logic-wise.
                //    We use unsafe to bypass Rust's borrow checker preventing multiple &mut to the same object on the stack,
                //    but conceptually this is a recursive call on the same thread.
                let vm = unsafe { &mut *vm_ptr };

                // Execute synchronously using the REAL VM
                vm.call_value(func, &args)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))
            } else {
                Err(anyhow::anyhow!("GUI Evaluator called without active VM"))
            }
        })
    }
}

// --- Helpers ---

fn value_as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => Some(*n),
        _ => None,
    }
}

// --- Native Functions ---

pub fn vm_gui_run(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "gui.run requires a render function".to_string(),
        ));
    }
    let render_fn = args[0].clone();

    // Parse options
    let mut width = 800.0;
    let mut height = 600.0;
    let mut title = "Achronyme App".to_string();

    if let Some(Value::Record(r)) = args.get(1) {
        let opts = r.borrow();
        if let Some(Value::Number(w)) = opts.get("width") {
            width = *w as f32;
        }
        if let Some(Value::Number(h)) = opts.get("height") {
            height = *h as f32;
        }
        if let Some(Value::String(t)) = opts.get("title") {
            title = t.clone();
        }
    }

    let viewport = achronyme_gui::runner::egui::ViewportBuilder::default()
        .with_inner_size([width, height])
        .with_title(&title);
    let native_options = achronyme_gui::runner::eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    // Store VM pointer in thread-local storage
    ACTIVE_VM.with(|cell| {
        *cell.borrow_mut() = Some(vm as *mut VM);
    });

    // Run GUI (Blocking)
    let result = run_native(&title, render_fn, Box::new(VmGuiEvaluator), native_options);

    // Clear VM pointer
    ACTIVE_VM.with(|cell| {
        *cell.borrow_mut() = None;
    });

    match result {
        Ok(_) => Ok(Value::Null),
        Err(e) => Err(VmError::Runtime(format!("GUI Error: {}", e))),
    }
}

pub fn vm_ui_label(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let text = args
        .get(0)
        .cloned()
        .unwrap_or(Value::String("".to_string()));
    let style = args.get(1).cloned().unwrap_or(Value::Null);

    let text_str = match text {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        v => format!("{:?}", v),
    };

    components::label(&text_str, &style);
    Ok(Value::Null)
}

pub fn vm_ui_button(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let text = args
        .get(0)
        .cloned()
        .unwrap_or(Value::String("".to_string()));
    let style = args.get(1).cloned().unwrap_or(Value::Null);

    let text_str = match text {
        Value::String(s) => s,
        _ => format!("{:?}", text),
    };

    let clicked = components::button(&text_str, &style);
    Ok(Value::Boolean(clicked))
}

pub fn vm_ui_text_input(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let signal = args.get(0).cloned().unwrap_or(Value::Null);
    let style = args.get(1).cloned().unwrap_or(Value::Null);

    if let Value::Signal(sig_rc) = &signal {
        let mut text = {
            let sig = sig_rc.borrow();
            match &sig.value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                v => format!("{:?}", v),
            }
        };

        let changed = components::text_input(&mut text, &style);

        if changed {
            crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::String(text))?;
        }
        Ok(Value::Boolean(changed))
    } else {
        let mut text = match &signal {
            Value::String(s) => s.clone(),
            v => format!("{:?}", v),
        };
        components::text_input(&mut text, &style);
        Ok(Value::Null)
    }
}

pub fn vm_ui_slider(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let signal = args.get(0).cloned().unwrap_or(Value::Null);
    let min = args.get(1).and_then(|v| value_as_f64(v)).unwrap_or(0.0);
    let max = args.get(2).and_then(|v| value_as_f64(v)).unwrap_or(100.0);
    let style = args.get(3).cloned().unwrap_or(Value::Null);

    if let Value::Signal(sig_rc) = &signal {
        let mut value = {
            let sig = sig_rc.borrow();
            value_as_f64(&sig.value).unwrap_or(0.0)
        };

        let changed = components::slider(&mut value, min, max, &style);

        if changed {
            crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::Number(value))?;
        }
        Ok(Value::Boolean(changed))
    } else {
        let mut val = value_as_f64(&signal).unwrap_or(0.0);
        components::slider(&mut val, min, max, &style);
        Ok(Value::Null)
    }
}

pub fn vm_ui_box(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let props = args.get(0).cloned().unwrap_or(Value::Null);

    let mut style = Value::Null;
    let mut children = Value::Null;

    if let Value::Record(r) = &props {
        let r = r.borrow();
        if let Some(s) = r.get("style") {
            style = s.clone();
        }
        if let Some(c) = r.get("children") {
            children = c.clone();
        }
    } else if let Value::String(_) = &props {
        style = props.clone();
        if let Some(c) = args.get(1) {
            children = c.clone();
        }
    }

    components::container(&style, || {
        if let Value::Function(_) = children {
            // Access the active VM from thread local
            ACTIVE_VM.with(|cell| {
                if let Some(vm_ptr) = *cell.borrow() {
                    let vm = unsafe { &mut *vm_ptr };
                    // Recursive execution on the same VM
                    let _ = vm.call_value(&children, &[]);
                }
            });
        }
    });

    Ok(Value::Null)
}

pub fn vm_ui_plot(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let title = args
        .get(0)
        .cloned()
        .unwrap_or(Value::String("Plot".to_string()));
    let options = args.get(1).cloned().unwrap_or(Value::Null);

    let title_str = match title {
        Value::String(s) => s,
        _ => "Plot".to_string(),
    };

    components::plot(&title_str, &options);
    Ok(Value::Null)
}

pub fn vm_ui_checkbox(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let signal = args.get(0).cloned().unwrap_or(Value::Null);
    let label = args
        .get(1)
        .cloned()
        .unwrap_or(Value::String("".to_string()));
    let style = args.get(2).cloned().unwrap_or(Value::Null);

    let label_str = match label {
        Value::String(s) => s,
        v => format!("{:?}", v),
    };

    if let Value::Signal(sig_rc) = &signal {
        let mut checked = {
            let sig = sig_rc.borrow();
            match &sig.value {
                Value::Boolean(b) => *b,
                _ => false,
            }
        };

        let changed = components::checkbox(&mut checked, &label_str, &style);

        if changed {
            crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::Boolean(checked))?;
        }
        Ok(Value::Boolean(changed))
    } else {
        // Static usage
        let mut checked = match &signal {
            Value::Boolean(b) => *b,
            _ => false,
        };
        components::checkbox(&mut checked, &label_str, &style);
        Ok(Value::Null)
    }
}

pub fn vm_ui_combobox(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let signal = args.get(0).cloned().unwrap_or(Value::Null);
    let options = args.get(1).cloned().unwrap_or(Value::Null);
    let style = args.get(2).cloned().unwrap_or(Value::Null);

    let options_vec: Vec<String> = match options {
        Value::Vector(v) => v
            .borrow()
            .iter()
            .map(|val| match val {
                Value::String(s) => s.clone(),
                v => format!("{:?}", v),
            })
            .collect(),
        _ => vec![],
    };

    if let Value::Signal(sig_rc) = &signal {
        let mut current = {
            let sig = sig_rc.borrow();
            match &sig.value {
                Value::String(s) => s.clone(),
                v => format!("{:?}", v),
            }
        };

        let changed = components::combobox(&mut current, &options_vec, &style);

        if changed {
            crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::String(current))?;
        }
        Ok(Value::Boolean(changed))
    } else {
        let mut current = match &signal {
            Value::String(s) => s.clone(),
            v => format!("{:?}", v),
        };
        components::combobox(&mut current, &options_vec, &style);
        Ok(Value::Null)
    }
}

pub fn vm_ui_radio(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let signal = args.get(0).cloned().unwrap_or(Value::Null);
    let value_to_select = args.get(1).cloned().unwrap_or(Value::Null);
    let label = args
        .get(2)
        .cloned()
        .unwrap_or(Value::String("".to_string()));
    let style = args.get(3).cloned().unwrap_or(Value::Null);

    let label_str = match label {
        Value::String(s) => s,
        v => format!("{:?}", v),
    };

    let val_str = match value_to_select {
        Value::String(s) => s,
        v => format!("{:?}", v),
    };

    if let Value::Signal(sig_rc) = &signal {
        let current = {
            let sig = sig_rc.borrow();
            match &sig.value {
                Value::String(s) => s.clone(),
                v => format!("{:?}", v),
            }
        };

        let selected = current == val_str;
        let clicked = components::radio(selected, &label_str, &style);

        if clicked {
            crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::String(val_str))?;
        }
        Ok(Value::Boolean(clicked))
    } else {
        let current = match &signal {
            Value::String(s) => s.clone(),
            v => format!("{:?}", v),
        };
        let selected = current == val_str;
        components::radio(selected, &label_str, &style);
        Ok(Value::Null)
    }
}

pub fn vm_ui_tabs(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let titles = args.get(0).cloned().unwrap_or(Value::Null);
    let signal = args.get(1).cloned().unwrap_or(Value::Null);
    let content_fn = args.get(2).cloned().unwrap_or(Value::Null);
    let style = args.get(3).cloned().unwrap_or(Value::Null);

    let titles_vec: Vec<String> = match titles {
        Value::Vector(v) => v
            .borrow()
            .iter()
            .map(|val| match val {
                Value::String(s) => s.clone(),
                v => format!("{:?}", v),
            })
            .collect(),
        _ => vec![],
    };

    let mut current_idx = 0;
    let mut is_signal = false;

    if let Value::Signal(sig_rc) = &signal {
        is_signal = true;
        let sig = sig_rc.borrow();
        current_idx = match &sig.value {
            Value::Number(n) => *n as usize,
            _ => 0,
        };
    } else if let Value::Number(n) = signal {
        current_idx = n as usize;
    }

    let new_idx = components::tabs(&titles_vec, current_idx, &style);

    if let Some(idx) = new_idx {
        if is_signal {
            if let Value::Signal(sig_rc) = &signal {
                crate::builtins::reactive::set_signal_value(vm, sig_rc, Value::Number(idx as f64))?;
            }
        }
        current_idx = idx;
    }

    if let Value::Function(_) = content_fn {
        ACTIVE_VM.with(|cell| {
            if let Some(vm_ptr) = *cell.borrow() {
                let vm = unsafe { &mut *vm_ptr };
                let _ = vm.call_value(&content_fn, &[Value::Number(current_idx as f64)]);
            }
        });
    }

    Ok(Value::Null)
}

pub fn vm_ui_collapsing(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let title = args
        .get(0)
        .cloned()
        .unwrap_or(Value::String("".to_string()));
    let children = args.get(1).cloned().unwrap_or(Value::Null);
    let style = args.get(2).cloned().unwrap_or(Value::Null);

    let title_str = match title {
        Value::String(s) => s,
        v => format!("{:?}", v),
    };

    components::collapsing(&title_str, &style, || {
        if let Value::Function(_) = children {
            ACTIVE_VM.with(|cell| {
                if let Some(vm_ptr) = *cell.borrow() {
                    let vm = unsafe { &mut *vm_ptr };
                    let _ = vm.call_value(&children, &[]);
                }
            });
        }
    });
    Ok(Value::Null)
}

pub fn vm_ui_scroll_area(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let children = args.get(0).cloned().unwrap_or(Value::Null);
    let style = args.get(1).cloned().unwrap_or(Value::Null);

    components::scroll_area(&style, || {
        if let Value::Function(_) = children {
            ACTIVE_VM.with(|cell| {
                if let Some(vm_ptr) = *cell.borrow() {
                    let vm = unsafe { &mut *vm_ptr };
                    let _ = vm.call_value(&children, &[]);
                }
            });
        }
    });
    Ok(Value::Null)
}

pub fn vm_ui_progress_bar(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let value = args.get(0).cloned().unwrap_or(Value::Number(0.0));
    let style = args.get(1).cloned().unwrap_or(Value::Null);

    let progress = match value {
        Value::Number(n) => n as f32,
        _ => 0.0,
    };

    components::progress_bar(progress, &style);
    Ok(Value::Null)
}

pub fn vm_ui_separator(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let style = args.get(0).cloned().unwrap_or(Value::Null);
    components::separator(&style);
    Ok(Value::Null)
}

pub fn vm_ui_quit(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    components::quit();
    Ok(Value::Null)
}
