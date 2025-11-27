//! Node and Tree structures for the Achronyme UI Engine
//!
//! This module defines the core data structures for representing UI as a tree
//! of nodes, following a retained-mode architecture.

use slotmap::{new_key_type, SlotMap};
use taffy::NodeId as TaffyNodeId;

new_key_type! {
    /// Unique identifier for a UI node in the tree
    pub struct NodeId;
}

/// The type of content a node represents
#[derive(Debug, Clone)]
pub enum NodeContent {
    /// A container (like a div/box) that holds children
    Container,
    /// A text label
    Text(String),
    /// A clickable button
    Button {
        /// Unique ID for click tracking
        id: u64,
        /// Button label text
        label: String,
    },
    /// A single-line text input
    TextInput {
        /// Unique ID for state management
        id: u64,
        /// Placeholder text when empty
        placeholder: String,
        /// Current text value
        value: String,
        /// Cursor position in the text
        cursor: usize,
    },
    /// A horizontal slider for numeric values
    Slider {
        /// Unique ID for state management
        id: u64,
        /// Minimum value
        min: f64,
        /// Maximum value
        max: f64,
        /// Current value (from signal)
        value: f64,
    },
    /// A checkbox for boolean values
    Checkbox {
        /// Unique ID for state management
        id: u64,
        /// Label text
        label: String,
        /// Current checked state
        checked: bool,
    },
    /// A progress bar (non-interactive)
    ProgressBar {
        /// Progress value (0.0 to 1.0)
        progress: f32,
    },
    /// A visual separator line
    Separator,
    /// A plot/chart for data visualization
    Plot {
        /// Plot title
        title: String,
        /// X-axis label
        x_label: String,
        /// Y-axis label
        y_label: String,
        /// Data series
        series: Vec<PlotSeries>,
    },
}

/// A single data series in a plot
#[derive(Debug, Clone)]
pub struct PlotSeries {
    /// Series name (for legend)
    pub name: String,
    /// Type of plot: "line", "scatter", "points"
    pub kind: PlotKind,
    /// Data points as (x, y) pairs
    pub data: Vec<(f64, f64)>,
    /// Line/point color as ARGB
    pub color: u32,
    /// Point radius (for scatter/points)
    pub radius: f32,
}

/// Type of plot visualization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlotKind {
    Line,
    Scatter,
}

/// Visual style properties for a node
#[derive(Debug, Clone, Default)]
pub struct NodeStyle {
    /// Background color as ARGB (0xAARRGGBB)
    pub background_color: Option<u32>,
    /// Background opacity (0.0 - 1.0)
    pub background_opacity: Option<f32>,
    /// Border color as ARGB
    pub border_color: Option<u32>,
    /// Border width in pixels
    pub border_width: f32,
    /// Border radius in pixels
    pub border_radius: f32,
    /// Text color as ARGB
    pub text_color: Option<u32>,
    /// Text opacity (0.0 - 1.0)
    pub text_opacity: Option<f32>,
    /// Font size in pixels
    pub font_size: f32,
    /// Bold text
    pub font_bold: bool,
    /// Italic text
    pub font_italic: bool,
    /// Monospace font
    pub font_monospace: bool,
    /// Text alignment ("left", "center", "right")
    pub text_align: Option<String>,
    /// Shadow level (0 = none, 1-5 = sizes)
    pub shadow_level: u8,
    /// Overall opacity (0.0 - 1.0)
    pub opacity: Option<f32>,
}

/// Computed layout information after Taffy calculates positions
#[derive(Debug, Clone, Default)]
pub struct ComputedLayout {
    /// X position relative to parent
    pub x: f32,
    /// Y position relative to parent
    pub y: f32,
    /// Computed width
    pub width: f32,
    /// Computed height
    pub height: f32,
}

/// A single node in the UI tree
#[derive(Debug)]
pub struct UiNode {
    /// What this node displays
    pub content: NodeContent,
    /// Visual styling
    pub style: NodeStyle,
    /// Layout results (populated after layout pass)
    pub layout: ComputedLayout,
    /// Reference to the corresponding Taffy node for layout calculations
    pub taffy_node: Option<TaffyNodeId>,
    /// Parent node (None for root)
    pub parent: Option<NodeId>,
    /// Child nodes
    pub children: Vec<NodeId>,
    /// Whether this node needs re-layout
    pub dirty: bool,
}

impl UiNode {
    /// Create a new container node
    pub fn container() -> Self {
        Self {
            content: NodeContent::Container,
            style: NodeStyle::default(),
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a new text node
    pub fn text(label: impl Into<String>) -> Self {
        Self {
            content: NodeContent::Text(label.into()),
            style: NodeStyle {
                text_color: Some(0xFFFFFFFF), // White by default
                font_size: 14.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a new button node
    pub fn button(id: u64, label: impl Into<String>) -> Self {
        Self {
            content: NodeContent::Button {
                id,
                label: label.into(),
            },
            style: NodeStyle {
                background_color: Some(0xFF3B82F6), // Blue
                text_color: Some(0xFFFFFFFF),
                border_radius: 4.0,
                font_size: 14.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Set background color
    pub fn with_background(mut self, color: u32) -> Self {
        self.style.background_color = Some(color);
        self
    }

    /// Set text color
    pub fn with_text_color(mut self, color: u32) -> Self {
        self.style.text_color = Some(color);
        self
    }

    /// Set border radius
    pub fn with_border_radius(mut self, radius: f32) -> Self {
        self.style.border_radius = radius;
        self
    }

    /// Set border
    pub fn with_border(mut self, width: f32, color: u32) -> Self {
        self.style.border_width = width;
        self.style.border_color = Some(color);
        self
    }

    /// Create a text input node
    pub fn text_input(id: u64, placeholder: impl Into<String>) -> Self {
        Self {
            content: NodeContent::TextInput {
                id,
                placeholder: placeholder.into(),
                value: String::new(),
                cursor: 0,
            },
            style: NodeStyle {
                background_color: Some(0xFF2D2D2D),
                text_color: Some(0xFFFFFFFF),
                border_color: Some(0xFF4B5563),
                border_width: 1.0,
                border_radius: 4.0,
                font_size: 14.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a slider node
    pub fn slider(id: u64, min: f64, max: f64, value: f64) -> Self {
        Self {
            content: NodeContent::Slider {
                id,
                min,
                max,
                value,
            },
            style: NodeStyle {
                background_color: Some(0xFF374151),
                border_radius: 4.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a checkbox node
    pub fn checkbox(id: u64, label: impl Into<String>, checked: bool) -> Self {
        Self {
            content: NodeContent::Checkbox {
                id,
                label: label.into(),
                checked,
            },
            style: NodeStyle {
                text_color: Some(0xFFFFFFFF),
                font_size: 14.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a progress bar node
    pub fn progress_bar(progress: f32) -> Self {
        Self {
            content: NodeContent::ProgressBar {
                progress: progress.clamp(0.0, 1.0),
            },
            style: NodeStyle {
                background_color: Some(0xFF374151),
                border_radius: 4.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a separator node
    pub fn separator() -> Self {
        Self {
            content: NodeContent::Separator,
            style: NodeStyle {
                background_color: Some(0xFF4B5563),
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }

    /// Create a plot node
    pub fn plot(
        title: impl Into<String>,
        x_label: impl Into<String>,
        y_label: impl Into<String>,
        series: Vec<PlotSeries>,
    ) -> Self {
        Self {
            content: NodeContent::Plot {
                title: title.into(),
                x_label: x_label.into(),
                y_label: y_label.into(),
                series,
            },
            style: NodeStyle {
                background_color: Some(0xFF1F2937),
                border_radius: 8.0,
                text_color: Some(0xFFFFFFFF),
                font_size: 12.0,
                ..Default::default()
            },
            layout: ComputedLayout::default(),
            taffy_node: None,
            parent: None,
            children: Vec::new(),
            dirty: true,
        }
    }
}

/// The UI tree - stores all nodes and manages the hierarchy
pub struct UiTree {
    /// Storage for all nodes
    nodes: SlotMap<NodeId, UiNode>,
    /// The root node of the tree
    root: Option<NodeId>,
}

impl UiTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        Self {
            nodes: SlotMap::with_key(),
            root: None,
        }
    }

    /// Insert a node into the tree (not yet attached to hierarchy)
    pub fn insert(&mut self, node: UiNode) -> NodeId {
        self.nodes.insert(node)
    }

    /// Set the root node
    pub fn set_root(&mut self, id: NodeId) {
        self.root = Some(id);
    }

    /// Get the root node ID
    pub fn root(&self) -> Option<NodeId> {
        self.root
    }

    /// Get a reference to a node
    pub fn get(&self, id: NodeId) -> Option<&UiNode> {
        self.nodes.get(id)
    }

    /// Get a mutable reference to a node
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut UiNode> {
        self.nodes.get_mut(id)
    }

    /// Add a child to a parent node
    pub fn add_child(&mut self, parent: NodeId, child: NodeId) {
        if let Some(child_node) = self.nodes.get_mut(child) {
            child_node.parent = Some(parent);
        }
        if let Some(parent_node) = self.nodes.get_mut(parent) {
            parent_node.children.push(child);
        }
    }

    /// Remove a node and all its children from the tree
    pub fn remove(&mut self, id: NodeId) {
        // First, collect children to remove
        let children: Vec<NodeId> = self
            .nodes
            .get(id)
            .map(|n| n.children.clone())
            .unwrap_or_default();

        // Recursively remove children
        for child in children {
            self.remove(child);
        }

        // Remove from parent's children list
        if let Some(node) = self.nodes.get(id) {
            if let Some(parent_id) = node.parent {
                if let Some(parent) = self.nodes.get_mut(parent_id) {
                    parent.children.retain(|&c| c != id);
                }
            }
        }

        // Remove the node itself
        self.nodes.remove(id);

        // Clear root if this was it
        if self.root == Some(id) {
            self.root = None;
        }
    }

    /// Iterate over all nodes
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &UiNode)> {
        self.nodes.iter()
    }

    /// Iterate over all nodes mutably
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (NodeId, &mut UiNode)> {
        self.nodes.iter_mut()
    }

    /// Get the number of nodes in the tree
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Mark a node and its ancestors as dirty (needs re-layout)
    pub fn mark_dirty(&mut self, id: NodeId) {
        let mut current = Some(id);
        while let Some(node_id) = current {
            if let Some(node) = self.nodes.get_mut(node_id) {
                if node.dirty {
                    break; // Already dirty, ancestors must be too
                }
                node.dirty = true;
                current = node.parent;
            } else {
                break;
            }
        }
    }

    /// Clear dirty flags for all nodes
    pub fn clear_dirty(&mut self) {
        for (_, node) in self.nodes.iter_mut() {
            node.dirty = false;
        }
    }
}

impl Default for UiTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_operations() {
        let mut tree = UiTree::new();

        // Create root
        let root = tree.insert(UiNode::container().with_background(0xFF1A1A1A));
        tree.set_root(root);

        // Add children
        let child1 = tree.insert(UiNode::text("Hello"));
        let child2 = tree.insert(UiNode::button(1, "Click Me"));

        tree.add_child(root, child1);
        tree.add_child(root, child2);

        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(root).unwrap().children.len(), 2);
        assert_eq!(tree.get(child1).unwrap().parent, Some(root));
    }

    #[test]
    fn test_dirty_propagation() {
        let mut tree = UiTree::new();

        let root = tree.insert(UiNode::container());
        tree.set_root(root);

        let child = tree.insert(UiNode::text("Text"));
        tree.add_child(root, child);

        let grandchild = tree.insert(UiNode::text("Nested"));
        tree.add_child(child, grandchild);

        // Clear dirty flags
        tree.clear_dirty();

        // Mark grandchild dirty - should propagate up
        tree.mark_dirty(grandchild);

        assert!(tree.get(grandchild).unwrap().dirty);
        assert!(tree.get(child).unwrap().dirty);
        assert!(tree.get(root).unwrap().dirty);
    }
}
