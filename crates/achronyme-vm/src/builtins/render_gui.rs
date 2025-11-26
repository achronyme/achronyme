//! Native GUI functions using achronyme-render (retained mode UI)
//!
//! This module provides the bridge between Achronyme scripts and the
//! achronyme-render UI engine. It uses a hybrid retained/reactive approach:
//! - The UI tree structure is retained for performance
//! - Signal bindings enable reactive updates when values change
//! - The render function is re-executed each frame to pick up signal changes

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_render::{run, AuiApp, NodeId, PlotKind, PlotSeries, WindowConfig};
use achronyme_types::sync::Shared;
use achronyme_types::value::SignalState;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// Global ID counter for widgets - NOTE: This counter is reset at the START of each frame
// to ensure STABLE widget IDs across frames. The key insight is that as long as the
// render function produces the same UI structure, widgets will get the same IDs.
static WIDGET_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_widget_id() -> u64 {
    WIDGET_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn reset_widget_id_counter() {
    WIDGET_ID_COUNTER.store(1, Ordering::SeqCst);
}

// --- Thread-Local State for UI Building ---
// During the render callback, we store the AuiApp being built
// and a stack of parent node IDs for nesting containers.

thread_local! {
    static BUILD_CONTEXT: RefCell<Option<BuildContext>> = const { RefCell::new(None) };
}

/// Binding between widget ID and signal for reactive updates
#[derive(Clone)]
pub enum SignalBinding {
    /// Text input bound to a string signal
    TextInput(Shared<SignalState>),
    /// Slider bound to a number signal
    Slider(Shared<SignalState>),
    /// Checkbox bound to a boolean signal
    Checkbox(Shared<SignalState>),
}

struct BuildContext {
    /// The AuiApp being built
    app: AuiApp,
    /// Stack of parent node IDs for nested containers
    parent_stack: Vec<NodeId>,
    /// VM pointer for callback execution (reserved for future event handling)
    vm_ptr: Option<*mut VM>,
    /// Signal bindings for reactive controls (widget_id -> signal)
    signal_bindings: HashMap<u64, SignalBinding>,
    /// Map of widget_id to NodeId for updating values
    widget_nodes: HashMap<u64, NodeId>,
}

impl BuildContext {
    fn new(config: WindowConfig) -> Self {
        Self {
            app: AuiApp::new(config),
            parent_stack: Vec::new(),
            vm_ptr: None,
            signal_bindings: HashMap::new(),
            widget_nodes: HashMap::new(),
        }
    }

    fn current_parent(&self) -> Option<NodeId> {
        self.parent_stack.last().copied()
    }

    /// Register a signal binding for a widget
    fn bind_signal(&mut self, widget_id: u64, node_id: NodeId, binding: SignalBinding) {
        self.signal_bindings.insert(widget_id, binding);
        self.widget_nodes.insert(widget_id, node_id);
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

/// ControlChange represents a change to a control value that needs to update a signal
#[derive(Debug, Clone)]
pub enum ControlChange {
    TextInput { widget_id: u64, value: String },
    Slider { widget_id: u64, value: f64 },
    Checkbox { widget_id: u64, checked: bool },
}

/// Sync signal bindings from BuildContext after each frame
/// IMPORTANT: This ONLY syncs widgets that the USER interacted with.
/// Widgets read their signal values during creation, so programmatic updates
/// (like signal.set() from buttons) are automatically reflected on rebuild.
///
/// NOTE: We do NOT call notify_signal_changed here because:
/// 1. We're already in a rebuild triggered by user interaction
/// 2. Calling notifier would cause an infinite loop (sync → notify → rebuild → sync...)
/// 3. The signal value is updated directly, effects will run on next VM tick
fn sync_signals_from_app(
    app: &achronyme_render::AuiApp,
    bindings: &HashMap<u64, SignalBinding>,
    widget_nodes: &HashMap<u64, NodeId>,
) {
    for (widget_id, binding) in bindings {
        let Some(&node_id) = widget_nodes.get(widget_id) else {
            continue;
        };

        // CRITICAL: Only sync user-modified widgets to signals.
        // The flow is:
        //   User interaction → widget state changes → mark_modified() → sync to signal
        //   Programmatic change → signal.set() → triggers rebuild → widgets read signal values
        // This prevents the race condition where we overwrite programmatic updates.
        if !app.was_node_modified(node_id) {
            continue;
        }

        match binding {
            SignalBinding::TextInput(sig_rc) => {
                if let Some(value) = app.get_text_input_value(node_id) {
                    let mut sig = sig_rc.write();
                    if let Value::String(ref old) = sig.value {
                        if *old != value {
                            sig.value = Value::String(value);
                        }
                    } else {
                        sig.value = Value::String(value);
                    }
                }
            }
            SignalBinding::Slider(sig_rc) => {
                if let Some(value) = app.get_slider_value(node_id) {
                    let mut sig = sig_rc.write();
                    if let Value::Number(old) = sig.value {
                        if (old - value).abs() > 0.001 {
                            sig.value = Value::Number(value);
                        }
                    } else {
                        sig.value = Value::Number(value);
                    }
                }
            }
            SignalBinding::Checkbox(sig_rc) => {
                if let Some(checked) = app.get_checkbox_checked(node_id) {
                    let mut sig = sig_rc.write();
                    if let Value::Boolean(old) = sig.value {
                        if old != checked {
                            sig.value = Value::Boolean(checked);
                        }
                    } else {
                        sig.value = Value::Boolean(checked);
                    }
                }
            }
        }
    }
}

/// Sync signal values TO the app (for when signals change externally)
fn sync_signals_to_app(
    app: &mut achronyme_render::AuiApp,
    bindings: &HashMap<u64, SignalBinding>,
    widget_nodes: &HashMap<u64, NodeId>,
) {
    for (widget_id, binding) in bindings {
        let Some(&node_id) = widget_nodes.get(widget_id) else {
            continue;
        };

        match binding {
            SignalBinding::TextInput(sig_rc) => {
                let sig = sig_rc.read();
                if let Value::String(ref value) = sig.value {
                    app.set_text_input_value(node_id, value);
                }
            }
            SignalBinding::Slider(sig_rc) => {
                let sig = sig_rc.read();
                if let Value::Number(value) = sig.value {
                    app.set_slider_value(node_id, value);
                }
            }
            SignalBinding::Checkbox(sig_rc) => {
                let sig = sig_rc.read();
                if let Value::Boolean(checked) = sig.value {
                    app.set_checkbox_checked(node_id, checked);
                }
            }
        }
    }
}

/// gui_run(render_fn, options) - Main entry point
/// Runs the GUI application with the given render function
/// The render function is called each frame to enable reactive updates via signals
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
    let ctx = BuildContext::new(config);

    // Set up the build context
    BUILD_CONTEXT.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });

    // Execute the render function to build the initial tree
    let _ = vm.call_value(&render_fn, &[]);

    // Extract the built app and signal bindings
    let (app, signal_bindings, widget_nodes) = BUILD_CONTEXT.with(|cell| {
        let mut borrow = cell.borrow_mut();
        borrow.take().map(|ctx| (ctx.app, ctx.signal_bindings, ctx.widget_nodes))
    }).ok_or_else(|| VmError::Runtime("gui_run: Failed to build UI".to_string()))?;

    // If there are no signal bindings, just run the app normally
    if signal_bindings.is_empty() {
        achronyme_render::run(app);
        return Ok(Value::Null);
    }

    // Run with frame callback for reactive updates
    run_with_callback(app, signal_bindings, widget_nodes, vm, render_fn);

    Ok(Value::Null)
}

/// Custom event for signal notifications
#[derive(Debug)]
enum UserEvent {
    SignalChanged,
}

/// Run the app with per-frame re-rendering (immediate-mode style)
/// This re-executes the render function each frame, allowing buttons to detect clicks
/// and signals to update reactively.
fn run_with_callback(
    app: achronyme_render::AuiApp,
    initial_bindings: HashMap<u64, SignalBinding>,
    initial_widget_nodes: HashMap<u64, NodeId>,
    vm: &mut VM,
    render_fn: Value,
) {
    use achronyme_render::winit::event_loop::{ControlFlow, EventLoop};

    // Create event loop with custom user event
    let event_loop = EventLoop::<UserEvent>::with_user_event().build().unwrap();
    event_loop.set_control_flow(ControlFlow::Wait); // Wait for events (efficient)

    // Register signal notifier to wake up the loop
    let proxy = event_loop.create_proxy();
    crate::builtins::reactive::register_signal_notifier(move || {
        let _ = proxy.send_event(UserEvent::SignalChanged);
    });

    // Store clicked buttons separately so they survive tree rebuilds
    let clicked_buttons: std::rc::Rc<std::cell::RefCell<Vec<u64>>> =
        std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let quit_requested: std::rc::Rc<std::cell::Cell<bool>> =
        std::rc::Rc::new(std::cell::Cell::new(false));

    // Run the event loop with per-frame rendering
    struct AppWrapper<'a> {
        app: achronyme_render::AuiApp,
        vm: &'a mut VM,
        render_fn: Value,
        config: achronyme_render::WindowConfig,
        needs_rebuild: bool,
        clicked_buttons: std::rc::Rc<std::cell::RefCell<Vec<u64>>>,
        quit_requested: std::rc::Rc<std::cell::Cell<bool>>,
        // Persist bindings to sync signals before rebuild
        last_bindings: HashMap<u64, SignalBinding>,
        last_widget_nodes: HashMap<u64, NodeId>,
    }

    impl<'a> achronyme_render::winit::application::ApplicationHandler<UserEvent> for AppWrapper<'a> {
        fn resumed(&mut self, event_loop: &achronyme_render::winit::event_loop::ActiveEventLoop) {
            self.app.resumed(event_loop);
        }

        fn user_event(&mut self, _event_loop: &achronyme_render::winit::event_loop::ActiveEventLoop, event: UserEvent) {
            match event {
                UserEvent::SignalChanged => {
                    // Signal changed, we need to rebuild UI to reflect new values
                    self.needs_rebuild = true;
                    self.app.request_redraw();
                }
            }
        }

        fn window_event(
            &mut self,
            event_loop: &achronyme_render::winit::event_loop::ActiveEventLoop,
            window_id: achronyme_render::winit::window::WindowId,
            event: achronyme_render::winit::event::WindowEvent,
        ) {
            use achronyme_render::winit::event::WindowEvent;

            // Handle the event first
            self.app.window_event(event_loop, window_id, event.clone());

            match &event {
                WindowEvent::MouseInput { state, .. } => {
                    use achronyme_render::winit::event::ElementState;
                    if *state == ElementState::Released {
                        // Copy clicked buttons from app to our persistent storage
                        // This happens AFTER window_event processes the click
                        let app_clicks: Vec<u64> = (1..=100)
                            .filter(|id| self.app.was_button_clicked(*id))
                            .collect();
                        if !app_clicks.is_empty() {
                            let mut clicks = self.clicked_buttons.borrow_mut();
                            for id in app_clicks {
                                if !clicks.contains(&id) {
                                    clicks.push(id);
                                }
                            }
                        }
                        // Now we need to rebuild to process the clicks
                        self.needs_rebuild = true;
                        self.app.request_redraw();
                    }
                }
                WindowEvent::KeyboardInput { .. } | WindowEvent::CursorMoved { .. } => {
                    // For keyboard/mouse move, also rebuild to update state if needed
                    // Optimization: We might not need full rebuild on cursor move unless hover effects
                    // For now, we keep it but ensure ControlFlow::Wait handles the rest
                    self.needs_rebuild = true;
                    self.app.request_redraw();
                }
                WindowEvent::RedrawRequested => {
                    // Check if quit was requested
                    if self.quit_requested.get() || self.app.is_quit_requested() {
                        event_loop.exit();
                        return;
                    }

                    // Re-execute render function for immediate-mode behavior
                    if self.needs_rebuild {
                        // 1. SYNC INPUTS TO SIGNALS
                        // Before destroying the tree, read current values from widgets and update signals
                        // This ensures that user input is captured into the signal system
                        sync_signals_from_app(&self.app, &self.last_bindings, &self.last_widget_nodes);

                        // Reset widget ID counter so IDs are stable across frames
                        reset_widget_id_counter();

                        // Get the clicked buttons before clearing
                        let pending_clicks: Vec<u64> = self.clicked_buttons.borrow().clone();

                        // Clear the tree but keep window/renderer state
                        self.app.clear_tree();

                        // Re-register pending clicks so ui_button can detect them
                        for id in &pending_clicks {
                            self.app.register_button_click(*id);
                        }

                        // Set up the build context
                        BUILD_CONTEXT.with(|cell| {
                            *cell.borrow_mut() = Some(BuildContext {
                                app: std::mem::take(&mut self.app),
                                parent_stack: Vec::new(),
                                vm_ptr: None,
                                signal_bindings: HashMap::new(),
                                widget_nodes: HashMap::new(),
                            });
                        });

                        // Store refs for the closure
                        let quit_ref = self.quit_requested.clone();

                        // Execute the render function
                        let result = self.vm.call_value(&self.render_fn, &[]);

                        // Check for errors or quit
                        if result.is_err() {
                            eprintln!("Render error: {:?}", result.err());
                        }

                        // Get the app back and SAVE BINDINGS
                        BUILD_CONTEXT.with(|cell| {
                            if let Some(mut ctx) = cell.borrow_mut().take() {
                                self.app = ctx.app;
                                // Save bindings for next frame
                                self.last_bindings = ctx.signal_bindings;
                                self.last_widget_nodes = ctx.widget_nodes;

                                // Check if quit was requested during render
                                if self.app.is_quit_requested() {
                                    quit_ref.set(true);
                                }
                            }
                        });

                        // Recalculate layout for the new tree!
                        self.app.compute_layout();

                        // Clear clicked buttons after they've been processed
                        self.clicked_buttons.borrow_mut().clear();
                        self.app.clear_clicked_buttons();
                        self.needs_rebuild = false;
                    }
                }
                _ => {}
            }
        }
    }

    // Store config for rebuilding
    let config = app.config.clone();

    let mut wrapper = AppWrapper {
        app,
        vm,
        render_fn,
        config,
        needs_rebuild: false, // Don't rebuild first frame - we already have the initial tree
        clicked_buttons,
        quit_requested,
        last_bindings: initial_bindings, // Use bindings from initial render
        last_widget_nodes: initial_widget_nodes,
    };

    let _ = event_loop.run_app(&mut wrapper);
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
/// Returns true if the button was clicked since the last frame
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
    let widget_id = next_widget_id();

    let was_clicked = with_build_context(|ctx| {
        // Check if this button was clicked before adding it
        let clicked = ctx.app.was_button_clicked(widget_id);

        let id = ctx.app.add_button(widget_id, &text, &style_str);

        // Add to parent or set as root
        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }

        clicked
    })?;

    Ok(Value::Boolean(was_clicked))
}

// Placeholder implementations for other UI functions
// These will be properly implemented as we expand the system

/// ui_text_input(signal_or_config, style) - Create a text input field
/// If first arg is a Signal, bind to it reactively
/// If first arg is a string, it's treated as the initial value (placeholder is empty)
/// If first arg is a record with {value, placeholder}, use both
pub fn vm_ui_text_input(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_text_input called outside of gui_run".to_string(),
        ));
    }

    let (initial_value, placeholder, signal_opt) = match args.get(0) {
        // Signal binding - read current value and remember the signal for updates
        Some(Value::Signal(sig_rc)) => {
            let sig = sig_rc.read();
            let value = match &sig.value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                v => format!("{:?}", v),
            };
            drop(sig);
            (value, String::new(), Some(sig_rc.clone()))
        }
        Some(Value::String(s)) => (s.clone(), String::new(), None),
        Some(Value::Record(r)) => {
            let r = r.read();
            // Check if 'value' is a signal
            let (value, signal) = match r.get("value") {
                Some(Value::Signal(sig_rc)) => {
                    let sig = sig_rc.read();
                    let v = match &sig.value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        val => format!("{:?}", val),
                    };
                    drop(sig);
                    (v, Some(sig_rc.clone()))
                }
                Some(Value::String(s)) => (s.clone(), None),
                _ => (String::new(), None),
            };
            let placeholder = r.get("placeholder").and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            }).unwrap_or_default();
            (value, placeholder, signal)
        }
        _ => (String::new(), "Enter text...".to_string(), None),
    };

    let style_str = parse_style_string(args.get(1).unwrap_or(&Value::Null));
    let widget_id = next_widget_id();

    with_build_context(|ctx| {
        let id = ctx.app.add_text_input(widget_id, &placeholder, &initial_value, &style_str);

        // Register signal binding if present
        if let Some(sig) = signal_opt.clone() {
            ctx.bind_signal(widget_id, id, SignalBinding::TextInput(sig));
        }

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::String(initial_value))
}

/// ui_slider(value_or_signal, min, max, style) - Create a slider control
/// If first arg is a Signal, bind to it reactively
/// Otherwise, value should be a number representing the current value
pub fn vm_ui_slider(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if !has_build_context() {
        return Err(VmError::Runtime(
            "ui_slider called outside of gui_run".to_string(),
        ));
    }

    let (value, signal_opt) = match args.get(0) {
        Some(Value::Signal(sig_rc)) => {
            let sig = sig_rc.read();
            let v = match &sig.value {
                Value::Number(n) => *n,
                _ => 0.0,
            };
            drop(sig);
            (v, Some(sig_rc.clone()))
        }
        Some(Value::Number(n)) => (*n, None),
        _ => (0.0, None),
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

        // Register signal binding if present
        if let Some(sig) = signal_opt.clone() {
            ctx.bind_signal(widget_id, id, SignalBinding::Slider(sig));
        }

        if let Some(parent) = ctx.current_parent() {
            ctx.app.add_child(parent, id);
        } else {
            ctx.app.set_root(id);
        }
    })?;

    Ok(Value::Number(value))
}

/// ui_checkbox(label, checked_or_signal, style) - Create a checkbox
/// If second arg is a Signal, bind to it reactively
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

    let (checked, signal_opt) = match args.get(1) {
        Some(Value::Signal(sig_rc)) => {
            let sig = sig_rc.read();
            let v = match &sig.value {
                Value::Boolean(b) => *b,
                _ => false,
            };
            drop(sig);
            (v, Some(sig_rc.clone()))
        }
        Some(Value::Boolean(b)) => (*b, None),
        _ => (false, None),
    };

    let style_str = parse_style_string(args.get(2).unwrap_or(&Value::Null));
    let widget_id = next_widget_id();

    with_build_context(|ctx| {
        let id = ctx.app.add_checkbox(widget_id, &label, checked, &style_str);

        // Register signal binding if present
        if let Some(sig) = signal_opt.clone() {
            ctx.bind_signal(widget_id, id, SignalBinding::Checkbox(sig));
        }

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

/// ui_quit() - Request the application to quit
pub fn vm_ui_quit(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
    with_build_context(|ctx| {
        ctx.app.request_quit();
    }).ok();
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
