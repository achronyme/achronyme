//! Achronyme UI Engine (AUI)
//!
//! A retained-mode UI engine with CSS Flexbox layout powered by Taffy.
//! This replaces the egui-based immediate-mode GUI to properly support
//! web-like styling and layout semantics.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                   Achronyme Script                   │
//! │  ui_box("flex-col items-center", () => { ... })     │
//! └──────────────────────┬──────────────────────────────┘
//!                        │ constructs
//!                        ▼
//! ┌─────────────────────────────────────────────────────┐
//! │                     UiTree                           │
//! │  Retained tree of UiNode structs with styling       │
//! └──────────────────────┬──────────────────────────────┘
//!                        │ synced to
//!                        ▼
//! ┌─────────────────────────────────────────────────────┐
//! │                  LayoutEngine (Taffy)                │
//! │  Computes Flexbox layout → x, y, width, height      │
//! └──────────────────────┬──────────────────────────────┘
//!                        │ feeds
//!                        ▼
//! ┌─────────────────────────────────────────────────────┐
//! │              WgpuRenderer (GPU) / SoftwareRenderer   │
//! │  Rasterizes nodes to screen                         │
//! └──────────────────────┬──────────────────────────────┘
//!                        │ displays via
//!                        ▼
//! ┌─────────────────────────────────────────────────────┐
//! │                  Window (winit)                      │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod events;
pub mod layout;
pub mod node;
pub mod style_parser;
pub mod text;

// Conditional rendering backends
#[cfg(feature = "wgpu-backend")]
pub mod wgpu_renderer;

#[cfg(feature = "software-backend")]
pub mod render;

// Re-export winit for consumers
pub use winit;

use events::{EventManager, MouseButton};
use layout::{LayoutEngine, LayoutStyle};
pub use events::Event;
pub use node::{NodeId, PlotKind, PlotSeries};
pub use style_parser::{parse_style, ParsedStyle};
use node::{UiNode, UiTree};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, MouseButton as WinitMouseButton, WindowEvent, KeyEvent};
use winit::keyboard::{Key, NamedKey};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowId};

// Re-export the appropriate renderer types
#[cfg(feature = "wgpu-backend")]
pub use wgpu_renderer::RenderState;

#[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
pub use render::RenderState;

/// Configuration for creating a window
#[derive(Clone)]
pub struct WindowConfig {
    pub title: String,
    pub width: u32,
    pub height: u32,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            title: "Achronyme".to_string(),
            width: 800,
            height: 600,
        }
    }
}

/// The main application state
pub struct AuiApp {
    /// Window configuration
    pub config: WindowConfig,
    /// The window (created on resume)
    window: Option<Arc<Window>>,
    /// The UI tree
    tree: UiTree,
    /// Layout styles for each node
    styles: HashMap<NodeId, LayoutStyle>,
    /// The layout engine
    layout_engine: LayoutEngine,
    /// Event manager for handling interactions
    events: EventManager,
    /// Root node ID
    root: Option<NodeId>,
    /// Current window size
    size: PhysicalSize<u32>,
    /// Current cursor position
    cursor_pos: PhysicalPosition<f64>,
    /// Track hovered node for visual feedback
    hovered_node: Option<NodeId>,
    /// Track pressed node for visual feedback
    pressed_node: Option<NodeId>,
    /// Track focused node for keyboard input
    focused_node: Option<NodeId>,
    /// Track if slider is being dragged
    dragging_slider: Option<NodeId>,
    /// Track clicked button widget IDs (cleared after each frame)
    clicked_buttons: Vec<u64>,
    /// Track nodes that were modified by user input this frame
    modified_nodes: HashSet<NodeId>,
    /// Flag to request app quit
    quit_requested: bool,

    // Backend-specific fields
    #[cfg(feature = "wgpu-backend")]
    renderer: Option<wgpu_renderer::WgpuRenderer>,

    #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
    renderer: render::SoftwareRenderer,
}

impl Default for AuiApp {
    fn default() -> Self {
        Self::new(WindowConfig::default())
    }
}

impl AuiApp {
    /// Create a new application
    pub fn new(config: WindowConfig) -> Self {
        Self {
            size: PhysicalSize::new(config.width, config.height),
            config,
            window: None,
            tree: UiTree::new(),
            styles: HashMap::new(),
            layout_engine: LayoutEngine::new(),
            events: EventManager::new(),
            root: None,
            cursor_pos: PhysicalPosition::new(0.0, 0.0),
            hovered_node: None,
            pressed_node: None,
            focused_node: None,
            dragging_slider: None,
            clicked_buttons: Vec::new(),
            modified_nodes: HashSet::new(),
            quit_requested: false,

            #[cfg(feature = "wgpu-backend")]
            renderer: None,

            #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
            surface: None,
            #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
            renderer: render::SoftwareRenderer::new(800, 600),
        }
    }

    /// Get mutable access to the UI tree for building
    pub fn tree_mut(&mut self) -> &mut UiTree {
        &mut self.tree
    }

    /// Get the styles map for modification
    pub fn styles_mut(&mut self) -> &mut HashMap<NodeId, LayoutStyle> {
        &mut self.styles
    }

    /// Set the root node
    pub fn set_root(&mut self, id: NodeId) {
        self.tree.set_root(id);
        self.root = Some(id);
    }

    /// Add a styled node using a Tailwind-like style string
    /// Returns the NodeId of the created node
    pub fn add_node(&mut self, content: node::NodeContent, style_str: &str) -> NodeId {
        let parsed = parse_style(style_str).unwrap_or_default();

        let node = UiNode {
            content,
            style: parsed.visual,
            layout: Default::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        };

        let id = self.tree.insert(node);
        self.styles.insert(id, parsed.layout);
        id
    }

    /// Add a container with style string
    pub fn add_container(&mut self, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::Container, style_str)
    }

    /// Add a text label with style string
    pub fn add_text(&mut self, text: &str, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::Text(text.to_string()), style_str)
    }

    /// Add a button with style string
    pub fn add_button(&mut self, id: u64, label: &str, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::Button { id, label: label.to_string() }, style_str)
    }

    /// Add a text input with style string
    pub fn add_text_input(&mut self, id: u64, placeholder: &str, initial_value: &str, style_str: &str) -> NodeId {
        self.add_node(
            node::NodeContent::TextInput {
                id,
                placeholder: placeholder.to_string(),
                value: initial_value.to_string(),
                cursor: initial_value.len(),
            },
            style_str,
        )
    }

    /// Add a slider with style string
    pub fn add_slider(&mut self, id: u64, min: f64, max: f64, value: f64, style_str: &str) -> NodeId {
        self.add_node(
            node::NodeContent::Slider { id, min, max, value },
            style_str,
        )
    }

    /// Add a checkbox with style string
    pub fn add_checkbox(&mut self, id: u64, label: &str, checked: bool, style_str: &str) -> NodeId {
        self.add_node(
            node::NodeContent::Checkbox {
                id,
                label: label.to_string(),
                checked,
            },
            style_str,
        )
    }

    /// Add a progress bar with style string
    pub fn add_progress_bar(&mut self, progress: f32, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::ProgressBar { progress }, style_str)
    }

    /// Add a separator with style string
    pub fn add_separator(&mut self, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::Separator, style_str)
    }

    /// Add a plot with style string
    pub fn add_plot(
        &mut self,
        title: &str,
        x_label: &str,
        y_label: &str,
        series: Vec<node::PlotSeries>,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Plot {
                title: title.to_string(),
                x_label: x_label.to_string(),
                y_label: y_label.to_string(),
                series,
            },
            style_str,
        )
    }

    /// Add a child to a parent node
    pub fn add_child(&mut self, parent: NodeId, child: NodeId) {
        self.tree.add_child(parent, child);
    }

    /// Request a redraw
    pub fn request_redraw(&self) {
        if let Some(window) = &self.window {
            window.request_redraw();
        }
    }

    /// Register a click handler for a node
    pub fn on_click(&mut self, node: NodeId, callback: impl Fn(&events::Event) + Send + Sync + 'static) {
        self.events.on_click(node, callback);
    }

    /// Register a hover enter handler
    pub fn on_hover_enter(&mut self, node: NodeId, callback: impl Fn(&events::Event) + Send + Sync + 'static) {
        self.events.on_hover_enter(node, callback);
    }

    /// Register a hover leave handler
    pub fn on_hover_leave(&mut self, node: NodeId, callback: impl Fn(&events::Event) + Send + Sync + 'static) {
        self.events.on_hover_leave(node, callback);
    }

    /// Get the currently hovered node (for styling)
    pub fn hovered(&self) -> Option<NodeId> {
        self.hovered_node
    }

    /// Get the currently pressed node (for styling)
    pub fn pressed(&self) -> Option<NodeId> {
        self.pressed_node
    }

    /// Get access to the event manager
    pub fn events_mut(&mut self) -> &mut EventManager {
        &mut self.events
    }

    /// Get the currently focused node
    pub fn focused(&self) -> Option<NodeId> {
        self.focused_node
    }

    /// Set focus to a specific node
    pub fn set_focus(&mut self, node: Option<NodeId>) {
        self.focused_node = node;
    }

    /// Check if a button with the given widget_id was clicked this frame
    pub fn was_button_clicked(&self, widget_id: u64) -> bool {
        self.clicked_buttons.contains(&widget_id)
    }

    /// Register that a button was clicked (by widget_id)
    pub fn register_button_click(&mut self, widget_id: u64) {
        if !self.clicked_buttons.contains(&widget_id) {
            self.clicked_buttons.push(widget_id);
        }
    }

    /// Clear clicked buttons (call at the start of each frame)
    pub fn clear_clicked_buttons(&mut self) {
        self.clicked_buttons.clear();
    }

    /// Check if a node was modified by user input this frame
    pub fn was_node_modified(&self, node_id: NodeId) -> bool {
        self.modified_nodes.contains(&node_id)
    }

    /// Mark a node as modified (internal use)
    fn mark_modified(&mut self, node_id: NodeId) {
        self.modified_nodes.insert(node_id);
    }

    /// Clear modified status (call at start of frame)
    pub fn clear_modified_nodes(&mut self) {
        self.modified_nodes.clear();
    }

    /// Request the app to quit
    pub fn request_quit(&mut self) {
        self.quit_requested = true;
    }

    /// Check if quit was requested
    pub fn is_quit_requested(&self) -> bool {
        self.quit_requested
    }

    /// Clear the UI tree for rebuilding (for immediate-mode style rendering)
    pub fn clear_tree(&mut self) {
        self.tree = UiTree::new();
        self.styles.clear();
        self.root = None;
        self.modified_nodes.clear();
    }

    /// Handle keyboard input for focused control
    fn handle_keyboard_input(&mut self, key_event: &KeyEvent) {
        if key_event.state != ElementState::Pressed {
            return;
        }

        let Some(focused) = self.focused_node else {
            return;
        };

        let Some(node) = self.tree.get_mut(focused) else {
            return;
        };

        match &mut node.content {
            node::NodeContent::TextInput { value, cursor, .. } => {
                match &key_event.logical_key {
                    Key::Character(c) => {
                        // Insert character at cursor
                        let char_str = c.as_str();
                        value.insert_str(*cursor, char_str);
                        *cursor += char_str.len();
                    }
                    Key::Named(NamedKey::Space) => {
                        value.insert_str(*cursor, " ");
                        *cursor += 1;
                    }
                    Key::Named(NamedKey::Backspace) => {
                        if *cursor > 0 {
                            // Find previous char boundary
                            let prev = value[..*cursor].char_indices()
                                .last()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                            value.remove(prev);
                            *cursor = prev;
                        }
                    }
                    Key::Named(NamedKey::Delete) => {
                        if *cursor < value.len() {
                            value.remove(*cursor);
                        }
                    }
                    Key::Named(NamedKey::ArrowLeft) => {
                        if *cursor > 0 {
                            *cursor = value[..*cursor].char_indices()
                                .last()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                        }
                    }
                    Key::Named(NamedKey::ArrowRight) => {
                        if *cursor < value.len() {
                            *cursor = value[*cursor..].char_indices()
                                .nth(1)
                                .map(|(i, _)| *cursor + i)
                                .unwrap_or(value.len());
                        }
                    }
                    Key::Named(NamedKey::Home) => {
                        *cursor = 0;
                    }
                    Key::Named(NamedKey::End) => {
                        *cursor = value.len();
                    }
                    _ => {}
                }
                self.request_redraw();
            }
            _ => {}
        }
    }

    /// Handle click on interactive controls
    fn handle_control_click(&mut self, node_id: NodeId, local_x: f32, _local_y: f32) {
        let Some(node) = self.tree.get_mut(node_id) else {
            return;
        };

        match &mut node.content {
            node::NodeContent::TextInput { .. } => {
                // Focus the text input
                self.focused_node = Some(node_id);
            }
            node::NodeContent::Checkbox { checked, .. } => {
                // Toggle the checkbox
                *checked = !*checked;
                self.mark_modified(node_id);
            }
            node::NodeContent::Slider { min, max, value, .. } => {
                // Calculate value from click position
                let width = node.layout.width;
                if width > 0.0 {
                    let ratio = (local_x / width).clamp(0.0, 1.0) as f64;
                    *value = *min + ratio * (*max - *min);
                    self.mark_modified(node_id);
                }
            }
            node::NodeContent::Button { id, .. } => {
                // Register button click for immediate-mode style detection
                self.clicked_buttons.push(*id);
            }
            _ => {}
        }
        self.request_redraw();
    }

    /// Handle slider drag
    fn handle_slider_drag(&mut self, x: f32) {
        let Some(slider_id) = self.dragging_slider else {
            return;
        };

        let Some(node) = self.tree.get_mut(slider_id) else {
            return;
        };

        if let node::NodeContent::Slider { min, max, value, .. } = &mut node.content {
            let layout_x = node.layout.x;
            let width = node.layout.width;
            if width > 0.0 {
                let local_x = x - layout_x;
                let ratio = (local_x / width).clamp(0.0, 1.0) as f64;
                *value = *min + ratio * (*max - *min);
                self.mark_modified(slider_id);
                self.request_redraw();
            }
        }
    }

    /// Get the value of a text input by node id
    pub fn get_text_input_value(&self, node_id: NodeId) -> Option<String> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::TextInput { value, .. } = &node.content {
                Some(value.clone())
            } else {
                None
            }
        })
    }

    /// Get the value of a slider by node id
    pub fn get_slider_value(&self, node_id: NodeId) -> Option<f64> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::Slider { value, .. } = &node.content {
                Some(*value)
            } else {
                None
            }
        })
    }

    /// Get the checked state of a checkbox by node id
    pub fn get_checkbox_checked(&self, node_id: NodeId) -> Option<bool> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::Checkbox { checked, .. } = &node.content {
                Some(*checked)
            } else {
                None
            }
        })
    }

    /// Set the value of a text input
    pub fn set_text_input_value(&mut self, node_id: NodeId, new_value: &str) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::TextInput { value, cursor, .. } = &mut node.content {
                *value = new_value.to_string();
                *cursor = new_value.len();
            }
        }
    }

    /// Set the value of a slider
    pub fn set_slider_value(&mut self, node_id: NodeId, new_value: f64) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::Slider { value, min, max, .. } = &mut node.content {
                *value = new_value.clamp(*min, *max);
            }
        }
    }

    /// Set the checked state of a checkbox
    pub fn set_checkbox_checked(&mut self, node_id: NodeId, new_checked: bool) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::Checkbox { checked, .. } = &mut node.content {
                *checked = new_checked;
            }
        }
    }

    pub fn compute_layout(&mut self) {
        if let Some(root) = self.root {
            // Update root style to match actual window size
            if let Some(root_style) = self.styles.get_mut(&root) {
                root_style.width = Some(self.size.width as f32);
                root_style.height = Some(self.size.height as f32);
            }

            self.layout_engine
                .sync_tree(&mut self.tree, root, &self.styles);
            self.layout_engine.compute_layout(
                &mut self.tree,
                root,
                self.size.width as f32,
                self.size.height as f32,
            );
        }
    }

    #[cfg(feature = "wgpu-backend")]
    fn do_render(&mut self) {
        let Some(renderer) = &mut self.renderer else {
            return;
        };
        let Some(root) = self.root else {
            return;
        };

        let state = wgpu_renderer::RenderState {
            hovered: self.hovered_node,
            pressed: self.pressed_node,
            focused: self.focused_node,
        };
        renderer.render_tree(&self.tree, root, state);
    }

    #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
    fn do_render(&mut self) {
        use std::num::NonZeroU32;

        let Some(surface) = &mut self.surface else {
            return;
        };
        let Some(root) = self.root else {
            return;
        };

        let width = self.size.width;
        let height = self.size.height;

        // Resize surface buffer
        if surface
            .resize(
                NonZeroU32::new(width).unwrap_or(NonZeroU32::new(1).unwrap()),
                NonZeroU32::new(height).unwrap_or(NonZeroU32::new(1).unwrap()),
            )
            .is_err()
        {
            return;
        }

        // Get the buffer
        let mut buffer = match surface.buffer_mut() {
            Ok(b) => b,
            Err(_) => return,
        };

        // Render to the buffer with interactive state
        self.renderer.resize(width, height);
        let state = render::RenderState {
            hovered: self.hovered_node,
            pressed: self.pressed_node,
        };
        self.renderer.render_with_state(&mut buffer, &self.tree, root, state);

        // Present
        let _ = buffer.present();
    }
}

impl ApplicationHandler for AuiApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }

        let window_attrs = Window::default_attributes()
            .with_title(&self.config.title)
            .with_inner_size(LogicalSize::new(self.config.width, self.config.height));

        let window = Arc::new(event_loop.create_window(window_attrs).unwrap());
        self.size = window.inner_size();

        // Initialize backend
        #[cfg(feature = "wgpu-backend")]
        {
            self.renderer = Some(wgpu_renderer::WgpuRenderer::new(window.clone()));
        }

        #[cfg(all(feature = "software-backend", not(feature = "wgpu-backend")))]
        {
            let context = softbuffer::Context::new(window.clone()).unwrap();
            let surface = softbuffer::Surface::new(&context, window.clone()).unwrap();
            self.surface = Some(surface);
        }

        self.window = Some(window.clone());

        // Initial layout
        self.compute_layout();

        // Request initial draw
        window.request_redraw();
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
            }
            WindowEvent::Resized(new_size) => {
                self.size = new_size;

                #[cfg(feature = "wgpu-backend")]
                if let Some(renderer) = &mut self.renderer {
                    renderer.resize(new_size.width, new_size.height);
                }

                self.compute_layout();
                self.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                self.do_render();
            }
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor_pos = position;
                let x = position.x as f32;
                let y = position.y as f32;

                // Handle slider dragging
                if self.dragging_slider.is_some() {
                    self.handle_slider_drag(x);
                }

                if let Some(root) = self.root {
                    let events = self.events.handle_mouse_move(&self.tree, root, x, y);

                    // Update hover state
                    let new_hovered = self.events.hovered();
                    if new_hovered != self.hovered_node {
                        self.hovered_node = new_hovered;
                        self.request_redraw();
                    }

                    // Dispatch events
                    for mut evt in events {
                        self.events.dispatch(&self.tree, &mut evt);
                    }
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let mouse_btn = match button {
                    WinitMouseButton::Left => MouseButton::Left,
                    WinitMouseButton::Right => MouseButton::Right,
                    WinitMouseButton::Middle => MouseButton::Middle,
                    _ => return,
                };

                match state {
                    ElementState::Pressed => {
                        if let Some(mut evt) = self.events.handle_mouse_down(&self.tree, mouse_btn) {
                            self.pressed_node = Some(evt.target);

                            // Check if pressing a slider to start dragging
                            if let Some(node) = self.tree.get(evt.target) {
                                if matches!(node.content, node::NodeContent::Slider { .. }) {
                                    self.dragging_slider = Some(evt.target);
                                    // Immediately update slider value
                                    self.handle_control_click(evt.target, evt.local_x, evt.local_y);
                                }
                            }

                            self.events.dispatch(&self.tree, &mut evt);
                            self.request_redraw();
                        } else {
                            // Clicked outside any node - unfocus
                            self.focused_node = None;
                        }
                    }
                    ElementState::Released => {
                        // Stop slider dragging
                        self.dragging_slider = None;

                        let events = self.events.handle_mouse_up(&self.tree, mouse_btn);
                        self.pressed_node = None;

                        for mut evt in events {
                            // Handle control click on release (for checkboxes, text inputs)
                            if matches!(evt.event_type, events::EventType::Click(_)) {
                                self.handle_control_click(evt.target, evt.local_x, evt.local_y);
                            }
                            self.events.dispatch(&self.tree, &mut evt);
                        }
                        self.request_redraw();
                    }
                }
            }
            WindowEvent::KeyboardInput { event: key_event, .. } => {
                self.handle_keyboard_input(&key_event);
            }
            WindowEvent::CursorLeft { .. } => {
                // Mouse left window - clear hover state and stop dragging
                self.dragging_slider = None;
                if self.hovered_node.is_some() {
                    self.hovered_node = None;
                    self.request_redraw();
                }
            }
            _ => {}
        }
    }
}

/// Run the application
pub fn run(mut app: AuiApp) {
    let event_loop = EventLoop::new().unwrap();
    event_loop.set_control_flow(ControlFlow::Wait);
    event_loop.run_app(&mut app).unwrap();
}

/// Demo: Create a simple test UI
pub fn demo() {
    use taffy::prelude::*;

    let config = WindowConfig {
        title: "AUI Demo - GPU Accelerated".to_string(),
        width: 600,
        height: 400,
    };

    let mut app = AuiApp::new(config);

    // Build the UI tree
    let root = app.tree_mut().insert(UiNode::container());
    app.styles_mut().insert(
        root,
        LayoutStyle::column()
            .with_width(600.0)
            .with_height(400.0)
            .with_align_items(AlignItems::Center)
            .with_justify(JustifyContent::Center)
            .with_gap(16.0),
    );

    // Title label
    let title = app.tree_mut().insert(UiNode::text("AUI Engine Demo"));
    app.tree_mut().add_child(root, title);
    app.styles_mut().insert(
        title,
        LayoutStyle::default().with_width(200.0).with_height(30.0),
    );

    // Inner card (shrink-wrap, should be centered!)
    let card = app
        .tree_mut()
        .insert(UiNode::container().with_background(0xFF333333).with_border_radius(8.0));
    app.tree_mut().add_child(root, card);
    app.styles_mut().insert(
        card,
        LayoutStyle::column()
            .with_padding(20.0)
            .with_gap(12.0)
            .with_align_items(AlignItems::Center),
    );

    // Card content
    let label1 = app.tree_mut().insert(UiNode::text("This card is shrink-wrapped"));
    app.tree_mut().add_child(card, label1);
    app.styles_mut()
        .insert(label1, LayoutStyle::default().with_width(180.0).with_height(20.0));

    let label2 = app.tree_mut().insert(UiNode::text("And properly centered!"));
    app.tree_mut().add_child(card, label2);
    app.styles_mut()
        .insert(label2, LayoutStyle::default().with_width(150.0).with_height(20.0));

    let button = app.tree_mut().insert(UiNode::button(1, "Click Me"));
    app.tree_mut().add_child(card, button);
    app.styles_mut()
        .insert(button, LayoutStyle::default().with_width(100.0).with_height(32.0));

    // Footer
    let footer = app.tree_mut().insert(UiNode::text("Footer"));
    app.tree_mut().add_child(root, footer);
    app.styles_mut()
        .insert(footer, LayoutStyle::default().with_width(80.0).with_height(20.0));

    app.set_root(root);

    run(app);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let config = WindowConfig::default();
        let app = AuiApp::new(config);
        assert!(app.root.is_none());
        assert!(app.tree.is_empty());
    }
}
