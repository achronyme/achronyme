//! Layout Engine - Integrates Taffy for Flexbox layout
//!
//! This module bridges our UiTree with Taffy's layout calculations,
//! solving the CSS-like layout problem that egui couldn't handle.

use crate::node::{NodeId, UiTree};
use std::collections::HashMap;
use taffy::prelude::*;

/// Layout style configuration (maps to Taffy styles)
#[derive(Debug, Clone, Default)]
pub struct LayoutStyle {
    /// Flex direction (row or column)
    pub direction: FlexDirection,
    /// Main axis alignment (justify-content)
    pub justify_content: Option<JustifyContent>,
    /// Cross axis alignment (align-items)
    pub align_items: Option<AlignItems>,
    /// Gap between items
    pub gap: f32,
    /// Padding (all sides) - used if specific sides not set
    pub padding: f32,
    /// Individual padding sides
    pub padding_top: Option<f32>,
    pub padding_bottom: Option<f32>,
    pub padding_left: Option<f32>,
    pub padding_right: Option<f32>,
    /// Margin (all sides) - used if specific sides not set
    pub margin: f32,
    /// Individual margin sides
    pub margin_top: Option<f32>,
    pub margin_bottom: Option<f32>,
    pub margin_left: Option<f32>,
    pub margin_right: Option<f32>,
    /// Fixed width (None = auto, INFINITY = 100%)
    pub width: Option<f32>,
    /// Fixed height (None = auto, INFINITY = 100%)
    pub height: Option<f32>,
    /// Min width
    pub min_width: Option<f32>,
    /// Min height
    pub min_height: Option<f32>,
}

impl LayoutStyle {
    /// Convert to Taffy Style
    pub fn to_taffy_style(&self) -> Style {
        Style {
            display: Display::Flex,
            flex_direction: self.direction,
            justify_content: self.justify_content,
            align_items: self.align_items,
            gap: Size {
                width: length(self.gap),
                height: length(self.gap),
            },
            padding: Rect {
                left: length(self.padding_left.unwrap_or(self.padding)),
                right: length(self.padding_right.unwrap_or(self.padding)),
                top: length(self.padding_top.unwrap_or(self.padding)),
                bottom: length(self.padding_bottom.unwrap_or(self.padding)),
            },
            margin: Rect {
                left: length(self.margin_left.unwrap_or(self.margin)),
                right: length(self.margin_right.unwrap_or(self.margin)),
                top: length(self.margin_top.unwrap_or(self.margin)),
                bottom: length(self.margin_bottom.unwrap_or(self.margin)),
            },
            size: Size {
                width: self.width.map(|w| {
                    if w.is_infinite() {
                        Dimension::Percent(1.0) // w-full = 100%
                    } else {
                        length(w)
                    }
                }).unwrap_or(Dimension::Auto),
                height: self.height.map(|h| {
                    if h.is_infinite() {
                        Dimension::Percent(1.0) // h-full = 100%
                    } else {
                        length(h)
                    }
                }).unwrap_or(Dimension::Auto),
            },
            min_size: Size {
                width: self.min_width.map(length).unwrap_or(Dimension::Auto),
                height: self.min_height.map(length).unwrap_or(Dimension::Auto),
            },
            ..Default::default()
        }
    }

    /// Create a column layout
    pub fn column() -> Self {
        Self {
            direction: FlexDirection::Column,
            ..Default::default()
        }
    }

    /// Create a row layout
    pub fn row() -> Self {
        Self {
            direction: FlexDirection::Row,
            ..Default::default()
        }
    }

    /// Set gap
    pub fn with_gap(mut self, gap: f32) -> Self {
        self.gap = gap;
        self
    }

    /// Set padding
    pub fn with_padding(mut self, padding: f32) -> Self {
        self.padding = padding;
        self
    }

    /// Set main axis alignment
    pub fn with_justify(mut self, justify: JustifyContent) -> Self {
        self.justify_content = Some(justify);
        self
    }

    /// Set cross axis alignment
    pub fn with_align_items(mut self, align: AlignItems) -> Self {
        self.align_items = Some(align);
        self
    }

    /// Set fixed width
    pub fn with_width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }

    /// Set fixed height
    pub fn with_height(mut self, height: f32) -> Self {
        self.height = Some(height);
        self
    }
}

/// The layout engine that wraps Taffy and syncs with our UiTree
pub struct LayoutEngine {
    /// The Taffy tree for layout calculations
    taffy: TaffyTree,
    /// Mapping from our NodeId to Taffy's NodeId
    node_map: HashMap<NodeId, taffy::NodeId>,
    /// Reverse mapping
    reverse_map: HashMap<taffy::NodeId, NodeId>,
}

impl LayoutEngine {
    /// Create a new layout engine
    pub fn new() -> Self {
        Self {
            taffy: TaffyTree::new(),
            node_map: HashMap::new(),
            reverse_map: HashMap::new(),
        }
    }

    /// Sync the UiTree with Taffy's internal tree
    /// This should be called when nodes are added/removed/modified
    pub fn sync_tree(&mut self, tree: &mut UiTree, root: NodeId, styles: &HashMap<NodeId, LayoutStyle>) {
        // Clear existing Taffy nodes
        self.taffy.clear();
        self.node_map.clear();
        self.reverse_map.clear();

        // Recursively create Taffy nodes
        self.create_taffy_node(tree, root, styles);
    }

    fn create_taffy_node(
        &mut self,
        tree: &mut UiTree,
        node_id: NodeId,
        styles: &HashMap<NodeId, LayoutStyle>,
    ) -> Option<taffy::NodeId> {
        let node = tree.get(node_id)?;

        // Get layout style (or default)
        let layout_style = styles.get(&node_id).cloned().unwrap_or_default();
        let taffy_style = layout_style.to_taffy_style();

        // Get children IDs
        let children_ids: Vec<NodeId> = node.children.clone();

        // Recursively create child Taffy nodes
        let taffy_children: Vec<taffy::NodeId> = children_ids
            .iter()
            .filter_map(|&child_id| self.create_taffy_node(tree, child_id, styles))
            .collect();

        // Create this node in Taffy
        let taffy_node = self
            .taffy
            .new_with_children(taffy_style, &taffy_children)
            .ok()?;

        // Store mappings
        self.node_map.insert(node_id, taffy_node);
        self.reverse_map.insert(taffy_node, node_id);

        // Store reference in UiNode
        if let Some(ui_node) = tree.get_mut(node_id) {
            ui_node.taffy_node = Some(taffy_node);
        }

        Some(taffy_node)
    }

    /// Compute layout for the tree
    pub fn compute_layout(&mut self, tree: &mut UiTree, root: NodeId, available_width: f32, available_height: f32) {
        if let Some(&taffy_root) = self.node_map.get(&root) {
            // Compute layout with available space
            let available_space = Size {
                width: AvailableSpace::Definite(available_width),
                height: AvailableSpace::Definite(available_height),
            };

            if self.taffy.compute_layout(taffy_root, available_space).is_ok() {
                // Copy computed layouts back to UiTree
                self.copy_layouts_to_tree(tree, root, 0.0, 0.0);
            }
        }
    }

    fn copy_layouts_to_tree(&self, tree: &mut UiTree, node_id: NodeId, parent_x: f32, parent_y: f32) {
        let taffy_node = match self.node_map.get(&node_id) {
            Some(&tn) => tn,
            None => return,
        };

        let layout = match self.taffy.layout(taffy_node) {
            Ok(l) => l,
            Err(_) => return,
        };

        // Get children before mutable borrow
        let children: Vec<NodeId> = tree
            .get(node_id)
            .map(|n| n.children.clone())
            .unwrap_or_default();

        // Update the node's computed layout
        if let Some(node) = tree.get_mut(node_id) {
            node.layout.x = parent_x + layout.location.x;
            node.layout.y = parent_y + layout.location.y;
            node.layout.width = layout.size.width;
            node.layout.height = layout.size.height;
        }

        // Get absolute position for children
        let abs_x = parent_x + layout.location.x;
        let abs_y = parent_y + layout.location.y;

        // Recursively update children
        for child_id in children {
            self.copy_layouts_to_tree(tree, child_id, abs_x, abs_y);
        }
    }

    /// Get the computed layout for a node
    pub fn get_layout(&self, node_id: NodeId) -> Option<&taffy::Layout> {
        let taffy_node = self.node_map.get(&node_id)?;
        self.taffy.layout(*taffy_node).ok()
    }
}

impl Default for LayoutEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::UiNode;

    #[test]
    fn test_basic_layout() {
        let mut tree = UiTree::new();
        let mut engine = LayoutEngine::new();
        let mut styles = HashMap::new();

        // Create a root container
        let root = tree.insert(UiNode::container());
        tree.set_root(root);

        // Root style: column, centered
        styles.insert(
            root,
            LayoutStyle::column()
                .with_gap(10.0)
                .with_padding(20.0)
                .with_align_items(AlignItems::Center),
        );

        // Add two children
        let child1 = tree.insert(UiNode::text("Hello"));
        let child2 = tree.insert(UiNode::text("World"));
        tree.add_child(root, child1);
        tree.add_child(root, child2);

        // Children have fixed sizes
        styles.insert(child1, LayoutStyle::default().with_width(100.0).with_height(30.0));
        styles.insert(child2, LayoutStyle::default().with_width(150.0).with_height(30.0));

        // Sync and compute
        engine.sync_tree(&mut tree, root, &styles);
        engine.compute_layout(&mut tree, root, 400.0, 300.0);

        // Verify layouts were computed
        let root_layout = tree.get(root).unwrap();
        assert!(root_layout.layout.width > 0.0);
        assert!(root_layout.layout.height > 0.0);

        // Children should be centered (x position offset from container center)
        let c1 = tree.get(child1).unwrap();
        let c2 = tree.get(child2).unwrap();

        // Both should have their heights
        assert_eq!(c1.layout.height, 30.0);
        assert_eq!(c2.layout.height, 30.0);

        // child2 is wider, so child1 should be more centered
        // In a centered column, the wider element is at the edge
        println!("Child1 x: {}, Child2 x: {}", c1.layout.x, c2.layout.x);
    }

    #[test]
    fn test_shrinkwrap_centering() {
        // This is THE test - the problem egui couldn't solve
        let mut tree = UiTree::new();
        let mut engine = LayoutEngine::new();
        let mut styles = HashMap::new();

        // Root: full size, center children
        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        styles.insert(
            root,
            LayoutStyle::column()
                .with_width(400.0)
                .with_height(300.0)
                .with_align_items(AlignItems::Center)
                .with_justify(JustifyContent::Center),
        );

        // Inner box: NO explicit size (shrink-wrap)
        let inner = tree.insert(UiNode::container().with_background(0xFF333333));
        tree.add_child(root, inner);
        styles.insert(
            inner,
            LayoutStyle::column().with_gap(8.0).with_padding(16.0),
        );

        // Content inside inner box
        let label = tree.insert(UiNode::text("Centered!"));
        tree.add_child(inner, label);
        styles.insert(label, LayoutStyle::default().with_width(80.0).with_height(20.0));

        // Compute layout
        engine.sync_tree(&mut tree, root, &styles);
        engine.compute_layout(&mut tree, root, 400.0, 300.0);

        // The inner box should be CENTERED, not taking full width
        let inner_node = tree.get(inner).unwrap();
        let inner_width = inner_node.layout.width;
        let inner_x = inner_node.layout.x;

        println!(
            "Inner box: x={}, y={}, w={}, h={}",
            inner_node.layout.x, inner_node.layout.y, inner_node.layout.width, inner_node.layout.height
        );

        // Inner should shrink-wrap: width = label_width + 2*padding = 80 + 32 = 112
        assert!(inner_width < 200.0, "Inner should shrink-wrap, not expand");

        // Inner should be centered: x ≈ (400 - inner_width) / 2
        let expected_x = (400.0 - inner_width) / 2.0;
        assert!(
            (inner_x - expected_x).abs() < 1.0,
            "Inner should be horizontally centered. Expected x≈{}, got x={}",
            expected_x,
            inner_x
        );
    }
}
