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
//! │                 SoftwareRenderer                     │
//! │  Rasterizes nodes to pixel buffer                   │
//! └──────────────────────┬──────────────────────────────┘
//!                        │ displays via
//!                        ▼
//! ┌─────────────────────────────────────────────────────┐
//! │                  Window (winit + softbuffer)         │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod layout;
pub mod node;
pub mod render;
pub mod style_parser;

use layout::{LayoutEngine, LayoutStyle};
pub use style_parser::{parse_style, ParsedStyle};
use node::{NodeId, UiNode, UiTree};
use render::SoftwareRenderer;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalSize};
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowId};

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
    config: WindowConfig,
    /// The window (created on resume)
    window: Option<Arc<Window>>,
    /// Softbuffer surface
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    /// The UI tree
    tree: UiTree,
    /// Layout styles for each node
    styles: HashMap<NodeId, LayoutStyle>,
    /// The layout engine
    layout_engine: LayoutEngine,
    /// The software renderer
    renderer: SoftwareRenderer,
    /// Root node ID
    root: Option<NodeId>,
    /// Current window size
    size: PhysicalSize<u32>,
}

impl AuiApp {
    /// Create a new application
    pub fn new(config: WindowConfig) -> Self {
        Self {
            size: PhysicalSize::new(config.width, config.height),
            config,
            window: None,
            surface: None,
            tree: UiTree::new(),
            styles: HashMap::new(),
            layout_engine: LayoutEngine::new(),
            renderer: SoftwareRenderer::new(800, 600),
            root: None,
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
    pub fn add_button(&mut self, label: &str, style_str: &str) -> NodeId {
        self.add_node(node::NodeContent::Button { label: label.to_string() }, style_str)
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

    fn do_layout(&mut self) {
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

    fn do_render(&mut self) {
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

        // Render to the buffer
        self.renderer.resize(width, height);
        self.renderer.render(&mut buffer, &self.tree, root);

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

        // Create softbuffer surface
        let context = softbuffer::Context::new(window.clone()).unwrap();
        let surface = softbuffer::Surface::new(&context, window.clone()).unwrap();

        self.window = Some(window.clone());
        self.surface = Some(surface);

        // Initial layout
        self.do_layout();

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
                self.do_layout();
                self.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                self.do_render();
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
        title: "AUI Demo - Shrink-Wrap Centering".to_string(),
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

    let button = app.tree_mut().insert(UiNode::button("Click Me"));
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
