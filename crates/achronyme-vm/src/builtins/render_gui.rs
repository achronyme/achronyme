//! Native GUI functions using achronyme-render (retained mode UI)
//!
//! This module provides the bridge between Achronyme scripts and the
//! achronyme-render UI engine. It uses a retained mode approach where
//! the UI tree is built once during the render function execution,
//! then the AuiApp manages layout and rendering.

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_render::{run, AuiApp, NodeId, PlotKind, PlotSeries, WindowConfig};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

// Global ID counter for widgets
static WIDGET_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_widget_id() -> u64 {
    WIDGET_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// --- Thread-Local State for UI Building ---
// During the render callback, we store the AuiApp being built
// and a stack of parent node IDs for nesting containers.

thread_local! {
    static BUILD_CONTEXT: RefCell<Option<BuildContext>> = const { RefCell::new(None) };
}

struct BuildContext {
    /// The AuiApp being built
    app: AuiApp,
    /// Stack of parent node IDs for nested containers
    parent_stack: Vec<NodeId>,
    /// VM pointer for callback execution (reserved for future event handling)
    vm_ptr: Option<*mut VM>,
}

impl BuildContext {
    fn new(config: WindowConfig) -> Self {
        Self {
            app: AuiApp::new(config),
            parent_stack: Vec::new(),
            vm_ptr: None,
        }
    }

    fn current_parent(&self) -> Option<NodeId> {
        self.parent_stack.last().copied()
    }
}

/// Execute a closure with the build context active
fn with_build_context<F, R>(f: F) -> Result<R, VmError>
where
    F: FnOnce(&mut BuildContext) -> R,
{
    BUILD_CONTEXT.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if let Some(ctx) = borrow.as_mut() {
            Ok(f(ctx))
        } else {
            Err(VmError::Runtime(
                "UI function called outside of gui_run context".to_string(),
            ))
        }
    })
}

/// Check if we're inside a build context
fn has_build_context() -> bool {
    BUILD_CONTEXT.with(|cell| cell.borrow().is_some())
}

// --- Style Parsing Helper ---

fn parse_style_string(style: &Value) -> String {
    match style {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => String::new(),
    }
}

// --- Native Functions ---

/// gui_run(render_fn, options) - Main entry point
/// Runs the GUI application with the given render function
pub fn vm_gui_run(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "gui_run requires a render function".to_string(),
        ));
    }
    let render_fn = args[0].clone();

    // Parse options
    let mut width = 800;
    let mut height = 600;
    let mut title = "Achronyme App".to_string();

    if let Some(Value::Record(r)) = args.get(1) {
        let opts = r.read();
        if let Some(Value::Number(w)) = opts.get("width") {
            width = *w as u32;
        }
        if let Some(Value::Number(h)) = opts.get("height") {
            height = *h as u32;
        }
        if let Some(Value::String(t)) = opts.get("title") {
            title = t.clone();
        }
    }

    // Create the build context with AuiApp
    let config = WindowConfig {
        title,
        width,
        height,
    };
    let mut ctx = BuildContext::new(config);
    ctx.vm_ptr = Some(vm as *mut VM);

    // Set up the build context
    BUILD_CONTEXT.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });

    // Execute the render function to build the tree
    let _ = vm.call_value(&render_fn, &[]);

    // Extract the built app
    let app = BUILD_CONTEXT.with(|cell| {
        let mut borrow = cell.borrow_mut();
        borrow.take().map(|ctx| ctx.app)
    });

    // If no app was created, return early
    let app = match app {
        Some(a) => a,
        None => {
            return Err(VmError::Runtime(
                "gui_run: Failed to build UI".to_string(),
            ));
        }
    };

    // Run the app (blocking)
    run(app);

    Ok(Value::Null)
}

/// ui_box(style, children_fn) - Create a container
pub fn vm_ui_box(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_box called outside of gui_run".to_string(),
        ));
    }

    let style_str = if let Some(Value::String(s)) = args.get(0) {
        s.clone()
    } else if let Some(Value::Record(r)) = args.get(0) {
        // Handle { style: "...", children: fn }
        let r = r.read();
        r.get("style")
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let children_fn = if let Some(Value::Record(r)) = args.get(0) {
        let r = r.read();
        r.get("children").cloned()
    } else {
        args.get(1).cloned()
    };

    // Create the container node using AuiApp's API
    let node_id = with_build_context(|ctx| {
        let id = ctx.app.add_container(&style_str);

        // If this is the first node (no parent), make it root
        if ctx.parent_stack.is_empty() {
            ctx.app.set_root(id);
        } else {
            // Add to current parent
            if let Some(parent) = ctx.current_parent() {
                ctx.app.add_child(parent, id);
            }
        }

        id
    })?;

    // Execute children with this node as parent
    if let Some(children) = children_fn {
        if matches!(children, Value::Function(_)) {
            with_build_context(|ctx| {
                ctx.parent_stack.push(node_id);
            })?;

            // Execute children
            let _ = vm.call_value(&children, &[]);

            with_build_context(|ctx| {
                ctx.parent_stack.pop();
            })?;
        }
    }

    Ok(Value::Null)
}

/// ui_label(text, style) - Create a text label
pub fn vm_ui_label(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_label called outside of gui_run".to_string(),
        ));
    }

    let text = match args.get(0) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(v) => format!("{:?}", v),
        None => String::new(),
    };

    let style_str = parse_style_string(args.get(1).unwrap_or(&Value::Null));

    with_build_context(|ctx| {
        let id = ctx.app.add_text(&text, &style_str);

        // Add to parent or set as root
        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Null)
}

/// ui_button(text, style) - Create a button
pub fn vm_ui_button(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_button called outside of gui_run".to_string(),
        ));
    }

    let text = match args.get(0) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => format!("{:?}", v),
        None => String::new(),
    };

    let style_str = parse_style_string(args.get(1).unwrap_or(&Value::Null));

    with_build_context(|ctx| {
        let id = ctx.app.add_button(&text, &style_str);

        // Add to parent or set as root
        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    // For now, buttons don't return click state (retained mode)
    // TODO: Implement event callbacks
    Ok(Value::Boolean(false))
}

// Placeholder implementations for other UI functions
// These will be properly implemented as we expand the system

/// ui_text_input(placeholder, style) - Create a text input field
pub fn vm_ui_text_input(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_text_input called outside of gui_run".to_string(),
        ));
    }

    let placeholder = match args.get(0) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };

    let style_str = parse_style_string(args.get(1).unwrap_or(&Value::Null));
    let widget_id = next_widget_id();

    with_build_context(|ctx| {
        let id = ctx.app.add_text_input(widget_id, &placeholder, &style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::String(String::new()))
}

/// ui_slider(value, min, max, style) - Create a slider control
/// value should be a number representing the current value
pub fn vm_ui_slider(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_slider called outside of gui_run".to_string(),
        ));
    }

    let value = match args.get(0) {
        Some(Value::Number(n)) => *n,
        _ => 0.0,
    };

    let min = match args.get(1) {
        Some(Value::Number(n)) => *n,
        _ => 0.0,
    };

    let max = match args.get(2) {
        Some(Value::Number(n)) => *n,
        _ => 100.0,
    };

    let style_str = parse_style_string(args.get(3).unwrap_or(&Value::Null));
    let widget_id = next_widget_id();

    with_build_context(|ctx| {
        let id = ctx.app.add_slider(widget_id, min, max, value, &style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Number(value))
}

/// ui_checkbox(label, checked, style) - Create a checkbox
pub fn vm_ui_checkbox(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_checkbox called outside of gui_run".to_string(),
        ));
    }

    let label = match args.get(0) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };

    let checked = match args.get(1) {
        Some(Value::Boolean(b)) => *b,
        _ => false,
    };

    let style_str = parse_style_string(args.get(2).unwrap_or(&Value::Null));
    let widget_id = next_widget_id();

    with_build_context(|ctx| {
        let id = ctx.app.add_checkbox(widget_id, &label, checked, &style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Boolean(checked))
}

pub fn vm_ui_combobox(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement combobox
    Ok(Value::Boolean(false))
}

pub fn vm_ui_radio(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement radio
    Ok(Value::Boolean(false))
}

pub fn vm_ui_tabs(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement tabs
    Ok(Value::Null)
}

pub fn vm_ui_collapsing(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement collapsing
    Ok(Value::Null)
}

pub fn vm_ui_scroll_area(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement scroll area
    Ok(Value::Null)
}

/// ui_progress_bar(progress, style) - Create a progress bar
/// progress is a value between 0.0 and 1.0
pub fn vm_ui_progress_bar(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_progress_bar called outside of gui_run".to_string(),
        ));
    }

    let progress = match args.get(0) {
        Some(Value::Number(n)) => (*n as f32).clamp(0.0, 1.0),
        _ => 0.0,
    };

    let style_str = parse_style_string(args.get(1).unwrap_or(&Value::Null));

    with_build_context(|ctx| {
        let id = ctx.app.add_progress_bar(progress, &style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Null)
}

/// ui_separator(style) - Create a visual separator line
pub fn vm_ui_separator(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_separator called outside of gui_run".to_string(),
        ));
    }

    let style_str = parse_style_string(args.get(0).unwrap_or(&Value::Null));

    with_build_context(|ctx| {
        let id = ctx.app.add_separator(&style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Null)
}

pub fn vm_ui_quit(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    // TODO: Implement quit
    Ok(Value::Null)
}

/// ui_plot(config) - Create a plot/chart visualization
/// config is a record with: title, x_label, y_label, series
/// series is an array of: { name, kind: "line"|"scatter", data: [[x,y],...], color, radius }
pub fn vm_ui_plot(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_plot called outside of gui_run".to_string(),
        ));
    }

    let (title, x_label, y_label, series, style_str) = if let Some(Value::Record(r)) = args.get(0) {
        let r = r.read();
        eprintln!("[DEBUG ui_plot] Parsing record with keys: {:?}", r.keys().collect::<Vec<_>>());
        let title = match r.get("title") {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        let x_label = match r.get("x_label") {
            Some(Value::String(s)) => s.clone(),
            _ => "X".to_string(),
        };
        let y_label = match r.get("y_label") {
            Some(Value::String(s)) => s.clone(),
            _ => "Y".to_string(),
        };
        let style_str = match r.get("style") {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        eprintln!("[DEBUG ui_plot] title='{}', style='{}'", title, style_str);

        // Parse series array
        let mut plot_series = Vec::new();
        if let Some(Value::Vector(arr)) = r.get("series") {
            let arr = arr.read();
            for item in arr.iter() {
                if let Value::Record(sr) = item {
                    let sr = sr.read();
                    let name = match sr.get("name") {
                        Some(Value::String(s)) => s.clone(),
                        _ => String::new(),
                    };
                    let kind = match sr.get("kind") {
                        Some(Value::String(s)) if s == "scatter" => PlotKind::Scatter,
                        _ => PlotKind::Line,
                    };
                    let color = match sr.get("color") {
                        Some(Value::Number(n)) => *n as u32,
                        _ => 0xFF3B82F6, // Default blue
                    };
                    let radius = match sr.get("radius") {
                        Some(Value::Number(n)) => *n as f32,
                        _ => 3.0,
                    };

                    // Parse data points [[x, y], ...]
                    let mut data = Vec::new();
                    if let Some(Value::Vector(data_arr)) = sr.get("data") {
                        let data_arr = data_arr.read();
                        for point in data_arr.iter() {
                            if let Value::Vector(pt) = point {
                                let pt = pt.read();
                                let x = match pt.get(0) {
                                    Some(Value::Number(n)) => *n,
                                    _ => 0.0,
                                };
                                let y = match pt.get(1) {
                                    Some(Value::Number(n)) => *n,
                                    _ => 0.0,
                                };
                                data.push((x, y));
                            }
                        }
                    }

                    eprintln!("[DEBUG ui_plot] Series '{}' has {} data points", name, data.len());
                    plot_series.push(PlotSeries {
                        name,
                        kind,
                        data,
                        color,
                        radius,
                    });
                }
            }
        } else {
            eprintln!("[DEBUG ui_plot] No 'series' Vector found in record");
        }
        eprintln!("[DEBUG ui_plot] Total series: {}", plot_series.len());

        (title, x_label, y_label, plot_series, style_str)
    } else {
        eprintln!("[DEBUG ui_plot] args[0] is not a Record");
        (String::new(), "X".to_string(), "Y".to_string(), Vec::new(), String::new())
    };

    with_build_context(|ctx| {
        let id = ctx.app.add_plot(&title, &x_label, &y_label, series, &style_str);

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Null)
}
