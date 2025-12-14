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

pub use events::Event;
use events::{EventManager, MouseButton};
use layout::{LayoutEngine, LayoutStyle};
pub use node::{NodeId, PlotKind, PlotSeries};
use node::{UiNode, UiTree};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
pub use style_parser::{parse_style, ParsedStyle};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, KeyEvent, MouseButton as WinitMouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{Key, NamedKey};
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

/// Actions from control clicks (used to defer state updates)
enum ControlAction {
    Focus(u64),
    Modified(u64),
    ButtonClick(u64),
    RadioClick(u64, usize), // (widget_id, new_selected_index)
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
    /// Track pressed widget (by widget_id, survives tree rebuild)
    pressed_widget: Option<u64>,
    /// Track focused widget for keyboard input (by widget_id, survives tree rebuild)
    focused_widget: Option<u64>,
    /// Track if slider is being dragged (by widget_id, survives tree rebuild)
    dragging_slider: Option<u64>,
    /// Track clicked button widget IDs (cleared after each frame)
    clicked_buttons: Vec<u64>,
    /// Track widget IDs that were modified by user input this frame
    modified_widgets: HashSet<u64>,
    /// Map widget_id to current NodeId (updated each rebuild)
    widget_to_node: HashMap<u64, NodeId>,
    /// Map NodeId to widget_id (for reverse lookups)
    node_to_widget: HashMap<NodeId, u64>,
    /// Flag to indicate we're in the middle of a rebuild (tree is temporarily invalid)
    rebuilding: bool,
    /// Pending slider drag position (queued during rebuild)
    pending_slider_drag: Option<f32>,
    /// Pending mouse press (queued during rebuild): (x, y, button)
    pending_mouse_press: Option<(f32, f32)>,
    /// Pending radio button clicks: (widget_id, new_selected_index)
    /// These persist across rebuilds so radio clicks aren't lost during animation
    pending_radio_clicks: Vec<(u64, usize)>,
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
            pressed_widget: None,
            focused_widget: None,
            dragging_slider: None,
            clicked_buttons: Vec::new(),
            modified_widgets: HashSet::new(),
            widget_to_node: HashMap::new(),
            node_to_widget: HashMap::new(),
            rebuilding: false,
            pending_slider_drag: None,
            pending_mouse_press: None,
            pending_radio_clicks: Vec::new(),
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
        self.add_node(
            node::NodeContent::Button {
                id,
                label: label.to_string(),
            },
            style_str,
        )
    }

    /// Add a text input with style string
    pub fn add_text_input(
        &mut self,
        id: u64,
        placeholder: &str,
        initial_value: &str,
        style_str: &str,
    ) -> NodeId {
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
    pub fn add_slider(
        &mut self,
        id: u64,
        min: f64,
        max: f64,
        value: f64,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Slider {
                id,
                min,
                max,
                value,
            },
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

    /// Add a radio button with style string
    pub fn add_radio_button(
        &mut self,
        id: u64,
        label: &str,
        index: usize,
        selected: usize,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::RadioButton {
                id,
                label: label.to_string(),
                index,
                selected,
            },
            style_str,
        )
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
        x_range: Option<(f64, f64)>,
        y_range: Option<(f64, f64)>,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Plot {
                title: title.to_string(),
                x_label: x_label.to_string(),
                y_label: y_label.to_string(),
                series,
                x_range,
                y_range,
            },
            style_str,
        )
    }

    /// Add a dropdown selector with style string
    pub fn add_dropdown(
        &mut self,
        id: u64,
        options: Vec<String>,
        selected: usize,
        placeholder: &str,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Dropdown {
                id,
                options,
                selected,
                open: false,
                placeholder: placeholder.to_string(),
            },
            style_str,
        )
    }

    /// Add a tab header with style string
    pub fn add_tab_header(
        &mut self,
        id: u64,
        tabs: Vec<String>,
        active: usize,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::TabHeader {
                id,
                tabs,
                active,
            },
            style_str,
        )
    }

    /// Add a tooltip container with style string
    pub fn add_tooltip(
        &mut self,
        text: &str,
        visible: bool,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Tooltip {
                text: text.to_string(),
                visible,
            },
            style_str,
        )
    }

    /// Add a modal dialog with style string
    pub fn add_modal(
        &mut self,
        id: u64,
        title: &str,
        visible: bool,
        style_str: &str,
    ) -> NodeId {
        self.add_node(
            node::NodeContent::Modal {
                id,
                visible,
                title: title.to_string(),
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
    pub fn on_click(
        &mut self,
        node: NodeId,
        callback: impl Fn(&events::Event) + Send + Sync + 'static,
    ) {
        self.events.on_click(node, callback);
    }

    /// Register a hover enter handler
    pub fn on_hover_enter(
        &mut self,
        node: NodeId,
        callback: impl Fn(&events::Event) + Send + Sync + 'static,
    ) {
        self.events.on_hover_enter(node, callback);
    }

    /// Register a hover leave handler
    pub fn on_hover_leave(
        &mut self,
        node: NodeId,
        callback: impl Fn(&events::Event) + Send + Sync + 'static,
    ) {
        self.events.on_hover_leave(node, callback);
    }

    /// Get the currently hovered node (for styling)
    pub fn hovered(&self) -> Option<NodeId> {
        self.hovered_node
    }

    /// Get the currently pressed node (for styling)
    pub fn pressed(&self) -> Option<NodeId> {
        self.pressed_widget.and_then(|wid| self.widget_to_node.get(&wid).copied())
    }

    /// Get access to the event manager
    pub fn events_mut(&mut self) -> &mut EventManager {
        &mut self.events
    }

    /// Get the currently focused node
    pub fn focused(&self) -> Option<NodeId> {
        self.focused_widget.and_then(|wid| self.widget_to_node.get(&wid).copied())
    }

    /// Set focus to a specific node (looks up widget_id from node)
    pub fn set_focus(&mut self, node: Option<NodeId>) {
        self.focused_widget = node.and_then(|nid| self.node_to_widget.get(&nid).copied());
    }

    /// Set focus by widget_id (survives tree rebuilds)
    pub fn set_focus_widget(&mut self, widget_id: Option<u64>) {
        self.focused_widget = widget_id;
    }

    /// Get the currently focused widget_id
    pub fn focused_widget_id(&self) -> Option<u64> {
        self.focused_widget
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

    /// Get pending radio button clicks (widget_id, new_selected_index)
    /// These persist across rebuilds so radio clicks during animation aren't lost
    pub fn get_pending_radio_clicks(&self) -> &[(u64, usize)] {
        &self.pending_radio_clicks
    }

    /// Clear pending radio clicks (call after processing them)
    pub fn clear_pending_radio_clicks(&mut self) {
        self.pending_radio_clicks.clear();
    }

    /// Apply pending radio clicks to the tree
    /// Call this after rebuild to update radio button states
    pub fn apply_pending_radio_clicks(&mut self) {
        for (widget_id, new_index) in self.pending_radio_clicks.clone() {
            if let Some(&node_id) = self.widget_to_node.get(&widget_id) {
                if let Some(node) = self.tree.get_mut(node_id) {
                    if let node::NodeContent::RadioButton { selected, .. } = &mut node.content {
                        *selected = new_index;
                    }
                }
            }
        }
    }

    /// Check if a widget was modified by user input this frame (by widget_id)
    pub fn was_widget_modified(&self, widget_id: u64) -> bool {
        self.modified_widgets.contains(&widget_id)
    }

    /// Check if a node was modified by user input this frame
    pub fn was_node_modified(&self, node_id: NodeId) -> bool {
        self.node_to_widget.get(&node_id)
            .map(|wid| self.modified_widgets.contains(wid))
            .unwrap_or(false)
    }

    /// Mark a widget as modified (by widget_id, internal use)
    fn mark_widget_modified(&mut self, widget_id: u64) {
        self.modified_widgets.insert(widget_id);
    }

    /// Mark a node as modified (internal use) - looks up widget_id
    #[allow(dead_code)]
    fn mark_modified(&mut self, node_id: NodeId) {
        if let Some(&widget_id) = self.node_to_widget.get(&node_id) {
            self.modified_widgets.insert(widget_id);
        }
    }

    /// Clear modified status (call at start of frame)
    pub fn clear_modified_widgets(&mut self) {
        self.modified_widgets.clear();
    }

    /// Check if a slider is currently being dragged
    pub fn is_dragging_slider(&self) -> bool {
        self.dragging_slider.is_some()
    }

    /// Check if any widgets have been modified this frame
    pub fn has_modified_widgets(&self) -> bool {
        !self.modified_widgets.is_empty()
    }

    /// Get the set of modified widget IDs this frame
    pub fn modified_widget_ids(&self) -> &HashSet<u64> {
        &self.modified_widgets
    }

    /// Request the app to quit
    pub fn request_quit(&mut self) {
        self.quit_requested = true;
    }

    /// Check if quit was requested
    pub fn is_quit_requested(&self) -> bool {
        self.quit_requested
    }

    /// Begin rebuilding the UI tree
    /// Sets rebuilding flag to queue events instead of processing immediately
    pub fn begin_rebuild(&mut self) {
        self.rebuilding = true;
        self.tree.clear();
        self.styles.clear();
        self.root = None;
        // DON'T clear widget_to_node/node_to_widget here!
        // They'll be replaced atomically in finalize_rebuild()
        // Clear hovered_node since NodeIds are invalid now
        self.hovered_node = None;
        // Note: We DON'T clear focused_widget, dragging_slider, pressed_widget
        // because they use widget_id which survives rebuilds
    }

    /// Legacy clear_tree for compatibility - same as begin_rebuild
    pub fn clear_tree(&mut self) {
        self.begin_rebuild();
    }

    /// Finalize the rebuild by swapping in new widget mappings atomically
    /// Also processes any queued events (like slider drags and mouse presses)
    pub fn finalize_rebuild(&mut self, new_widget_to_node: HashMap<u64, NodeId>) {
        // Build reverse mapping
        let new_node_to_widget: HashMap<NodeId, u64> = new_widget_to_node
            .iter()
            .map(|(&wid, &nid)| (nid, wid))
            .collect();

        // Atomically replace both mappings
        self.widget_to_node = new_widget_to_node;
        self.node_to_widget = new_node_to_widget;

        // Mark rebuild as complete
        self.rebuilding = false;

        // CRITICAL: Refresh hover state after rebuild!
        // The old hover NodeId is invalid - do a fresh hit test at current cursor position
        // This ensures clicks work correctly even if the cursor didn't move after rebuild
        if let Some(root) = self.root {
            let x = self.cursor_pos.x as f32;
            let y = self.cursor_pos.y as f32;
            // This updates events.hovered with the new NodeId at current cursor position
            let _ = self.events.handle_mouse_move(&self.tree, root, x, y);
            // Also update our local hover tracking
            self.hovered_node = self.events.hovered();
        }

        // Process any pending mouse press that occurred during rebuild
        if let Some((x, y)) = self.pending_mouse_press.take() {
            self.process_pending_mouse_press(x, y);
        }

        // Process any pending slider drag that occurred during rebuild
        if let Some(x) = self.pending_slider_drag.take() {
            self.handle_slider_drag(x);
        }
    }

    /// Process a mouse press that was queued during rebuild
    fn process_pending_mouse_press(&mut self, x: f32, y: f32) {
        // Find what's under the cursor now that tree is rebuilt
        if let Some(root) = self.root {
            if let Some(mut evt) = self.events.handle_mouse_down_at(&self.tree, root, x, y, MouseButton::Left) {
                // Store pressed widget by widget_id
                if let Some(&widget_id) = self.node_to_widget.get(&evt.target) {
                    self.pressed_widget = Some(widget_id);
                }

                // Check if pressing a slider to start dragging
                if let Some(node) = self.tree.get(evt.target) {
                    if let node::NodeContent::Slider { id, .. } = &node.content {
                        self.dragging_slider = Some(*id);
                        self.handle_control_click(evt.target, evt.local_x, evt.local_y);
                    }
                }

                self.events.dispatch(&self.tree, &mut evt);
                self.request_redraw();
            }
        }
    }

    /// Check if we're currently rebuilding (tree is temporarily invalid)
    pub fn is_rebuilding(&self) -> bool {
        self.rebuilding
    }

    /// Register a widget with its NodeId (call after adding a widget to the tree)
    /// This allows interaction state to survive tree rebuilds
    pub fn register_widget(&mut self, widget_id: u64, node_id: NodeId) {
        self.widget_to_node.insert(widget_id, node_id);
        self.node_to_widget.insert(node_id, widget_id);
    }

    /// Get the NodeId for a widget_id (if it exists in current tree)
    pub fn get_widget_node(&self, widget_id: u64) -> Option<NodeId> {
        self.widget_to_node.get(&widget_id).copied()
    }

    /// Get the widget_id for a NodeId (if it's a widget)
    pub fn get_node_widget(&self, node_id: NodeId) -> Option<u64> {
        self.node_to_widget.get(&node_id).copied()
    }

    /// Handle keyboard input for focused control
    fn handle_keyboard_input(&mut self, key_event: &KeyEvent) {
        if key_event.state != ElementState::Pressed {
            return;
        }

        // Use widget_id to find the current NodeId
        let Some(widget_id) = self.focused_widget else {
            return;
        };

        let Some(&focused) = self.widget_to_node.get(&widget_id) else {
            return;
        };

        let Some(node) = self.tree.get_mut(focused) else {
            return;
        };

        // Track if the value was modified (not just cursor movement)
        let mut value_changed = false;

        match &mut node.content {
            node::NodeContent::TextInput { value, cursor, .. } => {
                match &key_event.logical_key {
                    Key::Character(c) => {
                        // Insert character at cursor
                        let char_str = c.as_str();
                        value.insert_str(*cursor, char_str);
                        *cursor += char_str.len();
                        value_changed = true;
                    }
                    Key::Named(NamedKey::Space) => {
                        value.insert_str(*cursor, " ");
                        *cursor += 1;
                        value_changed = true;
                    }
                    Key::Named(NamedKey::Backspace) => {
                        if *cursor > 0 {
                            // Find previous char boundary
                            let prev = value[..*cursor]
                                .char_indices()
                                .last()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                            value.remove(prev);
                            *cursor = prev;
                            value_changed = true;
                        }
                    }
                    Key::Named(NamedKey::Delete) => {
                        if *cursor < value.len() {
                            value.remove(*cursor);
                            value_changed = true;
                        }
                    }
                    Key::Named(NamedKey::ArrowLeft) => {
                        if *cursor > 0 {
                            *cursor = value[..*cursor]
                                .char_indices()
                                .last()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                        }
                    }
                    Key::Named(NamedKey::ArrowRight) => {
                        if *cursor < value.len() {
                            *cursor = value[*cursor..]
                                .char_indices()
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

        // Mark as modified if value changed (so signal sync picks it up)
        if value_changed {
            self.mark_widget_modified(widget_id);
        }
    }

    /// Handle click on interactive controls
    fn handle_control_click(&mut self, node_id: NodeId, local_x: f32, _local_y: f32) {
        // First extract the information we need from the node
        let action = {
            let Some(node) = self.tree.get_mut(node_id) else {
                return;
            };

            match &mut node.content {
                node::NodeContent::TextInput { id, .. } => {
                    Some(ControlAction::Focus(*id))
                }
                node::NodeContent::Checkbox { id, checked, .. } => {
                    *checked = !*checked;
                    Some(ControlAction::Modified(*id))
                }
                node::NodeContent::Slider {
                    id,
                    min,
                    max,
                    value,
                } => {
                    let width = node.layout.width;
                    if width > 0.0 {
                        let ratio = (local_x / width).clamp(0.0, 1.0) as f64;
                        *value = *min + ratio * (*max - *min);
                        Some(ControlAction::Modified(*id))
                    } else {
                        None
                    }
                }
                node::NodeContent::RadioButton {
                    id,
                    index,
                    selected,
                    ..
                } => {
                    // Select this radio button (update selected to this index)
                    let new_index = *index;
                    *selected = new_index;
                    // Use RadioClick so click persists across rebuilds during animation
                    Some(ControlAction::RadioClick(*id, new_index))
                }
                node::NodeContent::Button { id, .. } => {
                    Some(ControlAction::ButtonClick(*id))
                }
                node::NodeContent::Dropdown {
                    id,
                    open,
                    ..
                } => {
                    if *open {
                        // Click on dropdown list - toggle closed
                        // Selection of items would need local_y coordinate
                        *open = false;
                        Some(ControlAction::Modified(*id))
                    } else {
                        // Toggle dropdown open
                        *open = true;
                        None
                    }
                }
                node::NodeContent::TabHeader {
                    id,
                    tabs,
                    active,
                } => {
                    // Calculate which tab was clicked based on local_x
                    let font_size = node.style.font_size.max(14.0);
                    let h_padding = 16.0;
                    let mut tab_x = 0.0f32;

                    for (i, tab) in tabs.iter().enumerate() {
                        let tab_width = tab.len() as f32 * font_size * 0.6 + h_padding * 2.0;
                        if local_x >= tab_x && local_x < tab_x + tab_width {
                            *active = i;
                            return; // Return early after finding the clicked tab
                        }
                        tab_x += tab_width;
                    }
                    Some(ControlAction::Modified(*id))
                }
                node::NodeContent::Modal { id, visible, .. } => {
                    // Click on modal close button area
                    let width = node.layout.width;
                    if local_x >= width - 40.0 && _local_y <= 48.0 {
                        *visible = false;
                        Some(ControlAction::Modified(*id))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        // Now apply the action (no longer borrowing tree)
        if let Some(action) = action {
            match action {
                ControlAction::Focus(widget_id) => {
                    self.focused_widget = Some(widget_id);
                }
                ControlAction::Modified(widget_id) => {
                    self.mark_widget_modified(widget_id);
                }
                ControlAction::ButtonClick(widget_id) => {
                    self.clicked_buttons.push(widget_id);
                }
                ControlAction::RadioClick(widget_id, new_index) => {
                    // Store radio click to persist across rebuilds
                    self.pending_radio_clicks.push((widget_id, new_index));
                    self.mark_widget_modified(widget_id);
                }
            }
        }

        self.request_redraw();
    }

    /// Handle slider drag
    fn handle_slider_drag(&mut self, x: f32) {
        // If we're rebuilding, queue the drag for later
        if self.rebuilding {
            self.pending_slider_drag = Some(x);
            return;
        }

        // dragging_slider now holds widget_id, not NodeId
        let Some(slider_widget_id) = self.dragging_slider else {
            return;
        };

        // Look up current NodeId from widget_id
        let Some(&slider_node_id) = self.widget_to_node.get(&slider_widget_id) else {
            // Widget not yet registered in new tree, queue for later
            self.pending_slider_drag = Some(x);
            return;
        };

        let Some(node) = self.tree.get_mut(slider_node_id) else {
            return;
        };

        if let node::NodeContent::Slider {
            min, max, value, ..
        } = &mut node.content
        {
            let layout_x = node.layout.x;
            let width = node.layout.width;
            if width > 0.0 {
                let local_x = x - layout_x;
                let ratio = (local_x / width).clamp(0.0, 1.0) as f64;
                *value = *min + ratio * (*max - *min);
                self.mark_widget_modified(slider_widget_id);
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

    /// Get the selected index of a radio button
    pub fn get_radio_selected(&self, node_id: NodeId) -> Option<usize> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::RadioButton { selected, .. } = &node.content {
                Some(*selected)
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
            if let node::NodeContent::Slider {
                value, min, max, ..
            } = &mut node.content
            {
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

    /// Set the selected index of a radio button group
    pub fn set_radio_selected(&mut self, node_id: NodeId, new_selected: usize) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::RadioButton { selected, .. } = &mut node.content {
                *selected = new_selected;
            }
        }
    }

    /// Get the selected index of a dropdown
    pub fn get_dropdown_selected(&self, node_id: NodeId) -> Option<usize> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::Dropdown { selected, .. } = &node.content {
                Some(*selected)
            } else {
                None
            }
        })
    }

    /// Set the selected index of a dropdown
    pub fn set_dropdown_selected(&mut self, node_id: NodeId, new_selected: usize) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::Dropdown { selected, options, .. } = &mut node.content {
                if new_selected < options.len() {
                    *selected = new_selected;
                }
            }
        }
    }

    /// Get the active tab index
    pub fn get_tab_active(&self, node_id: NodeId) -> Option<usize> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::TabHeader { active, .. } = &node.content {
                Some(*active)
            } else {
                None
            }
        })
    }

    /// Set the active tab index
    pub fn set_tab_active(&mut self, node_id: NodeId, new_active: usize) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::TabHeader { active, tabs, .. } = &mut node.content {
                if new_active < tabs.len() {
                    *active = new_active;
                }
            }
        }
    }

    /// Get the visibility of a modal
    pub fn get_modal_visible(&self, node_id: NodeId) -> Option<bool> {
        self.tree.get(node_id).and_then(|node| {
            if let node::NodeContent::Modal { visible, .. } = &node.content {
                Some(*visible)
            } else {
                None
            }
        })
    }

    /// Set the visibility of a modal
    pub fn set_modal_visible(&mut self, node_id: NodeId, new_visible: bool) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::Modal { visible, .. } = &mut node.content {
                *visible = new_visible;
            }
        }
    }

    /// Set the tooltip visibility
    pub fn set_tooltip_visible(&mut self, node_id: NodeId, new_visible: bool) {
        if let Some(node) = self.tree.get_mut(node_id) {
            if let node::NodeContent::Tooltip { visible, .. } = &mut node.content {
                *visible = new_visible;
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
        let Some(root) = self.root else {
            return;
        };

        // Resolve widget_ids to NodeIds before borrowing renderer
        let state = wgpu_renderer::RenderState {
            hovered: self.hovered_node,
            pressed: self.pressed(),
            focused: self.focused(),
        };

        let Some(renderer) = &mut self.renderer else {
            return;
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
        self.renderer
            .render_with_state(&mut buffer, &self.tree, root, state);

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
                        // If we're rebuilding, queue the mouse press for later
                        if self.rebuilding {
                            let x = self.cursor_pos.x as f32;
                            let y = self.cursor_pos.y as f32;
                            self.pending_mouse_press = Some((x, y));
                            return;
                        }

                        if let Some(mut evt) = self.events.handle_mouse_down(&self.tree, mouse_btn)
                        {
                            // Store pressed widget by widget_id (not NodeId)
                            if let Some(&widget_id) = self.node_to_widget.get(&evt.target) {
                                self.pressed_widget = Some(widget_id);
                            }

                            // Check if pressing a slider to start dragging
                            if let Some(node) = self.tree.get(evt.target) {
                                if let node::NodeContent::Slider { id, .. } = &node.content {
                                    // Store slider widget_id (survives tree rebuilds!)
                                    self.dragging_slider = Some(*id);
                                    // Immediately update slider value
                                    self.handle_control_click(evt.target, evt.local_x, evt.local_y);
                                }
                            }

                            self.events.dispatch(&self.tree, &mut evt);
                            self.request_redraw();
                        } else {
                            // Clicked outside any node - unfocus
                            self.focused_widget = None;
                        }
                    }
                    ElementState::Released => {
                        // Stop slider dragging
                        self.dragging_slider = None;

                        let events = self.events.handle_mouse_up(&self.tree, mouse_btn);
                        self.pressed_widget = None;

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
            WindowEvent::KeyboardInput {
                event: key_event, ..
            } => {
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
    let card = app.tree_mut().insert(
        UiNode::container()
            .with_background(0xFF333333)
            .with_border_radius(8.0),
    );
    app.tree_mut().add_child(root, card);
    app.styles_mut().insert(
        card,
        LayoutStyle::column()
            .with_padding(20.0)
            .with_gap(12.0)
            .with_align_items(AlignItems::Center),
    );

    // Card content
    let label1 = app
        .tree_mut()
        .insert(UiNode::text("This card is shrink-wrapped"));
    app.tree_mut().add_child(card, label1);
    app.styles_mut().insert(
        label1,
        LayoutStyle::default().with_width(180.0).with_height(20.0),
    );

    let label2 = app
        .tree_mut()
        .insert(UiNode::text("And properly centered!"));
    app.tree_mut().add_child(card, label2);
    app.styles_mut().insert(
        label2,
        LayoutStyle::default().with_width(150.0).with_height(20.0),
    );

    let button = app.tree_mut().insert(UiNode::button(1, "Click Me"));
    app.tree_mut().add_child(card, button);
    app.styles_mut().insert(
        button,
        LayoutStyle::default().with_width(100.0).with_height(32.0),
    );

    // Footer
    let footer = app.tree_mut().insert(UiNode::text("Footer"));
    app.tree_mut().add_child(root, footer);
    app.styles_mut().insert(
        footer,
        LayoutStyle::default().with_width(80.0).with_height(20.0),
    );

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
