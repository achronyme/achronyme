//! Layout Engine - Integrates Taffy for Flexbox layout
//!
//! This module bridges our UiTree with Taffy's layout calculations,
//! solving the CSS-like layout problem that egui couldn't handle.
//!
//! Uses MeasureFunction for intrinsic text/button sizing.

use crate::node::{NodeContent, NodeId, UiTree};
use crate::text::{FontWeight, TextRenderer};
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

/// Context for leaf nodes that need measurement (text, buttons, widgets)
#[derive(Debug, Clone)]
pub enum MeasureContext {
    /// Text node with content and font size
    Text { text: String, font_size: f32, bold: bool },
    /// Button with label and font size
    Button { label: String, font_size: f32 },
    /// Container (no measurement needed)
    Container,
    /// Text input field
    TextInput { placeholder: String, font_size: f32 },
    /// Slider control
    Slider,
    /// Checkbox with label
    Checkbox { label: String, font_size: f32 },
    /// Progress bar
    ProgressBar,
    /// Separator line
    Separator,
    /// Plot/Chart
    Plot,
}

/// The layout engine that wraps Taffy and syncs with our UiTree
pub struct LayoutEngine {
    /// The Taffy tree for layout calculations (with MeasureContext)
    taffy: TaffyTree<MeasureContext>,
    /// Mapping from our NodeId to Taffy's NodeId
    node_map: HashMap<NodeId, taffy::NodeId>,
    /// Reverse mapping
    reverse_map: HashMap<taffy::NodeId, NodeId>,
    /// Text renderer for measuring text
    text_renderer: TextRenderer,
}

impl LayoutEngine {
    /// Create a new layout engine
    pub fn new() -> Self {
        Self {
            taffy: TaffyTree::new(),
            node_map: HashMap::new(),
            reverse_map: HashMap::new(),
            text_renderer: TextRenderer::new(),
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

        // Create measure context based on node content
        let measure_context = match &node.content {
            NodeContent::Text(text) => MeasureContext::Text {
                text: text.clone(),
                font_size: node.style.font_size,
                bold: node.style.font_bold,
            },
            NodeContent::Button { label, .. } => MeasureContext::Button {
                label: label.clone(),
                font_size: node.style.font_size,
            },
            NodeContent::Container => MeasureContext::Container,
            NodeContent::TextInput { placeholder, .. } => MeasureContext::TextInput {
                placeholder: placeholder.clone(),
                font_size: node.style.font_size,
            },
            NodeContent::Slider { .. } => MeasureContext::Slider,
            NodeContent::Checkbox { label, .. } => MeasureContext::Checkbox {
                label: label.clone(),
                font_size: node.style.font_size,
            },
            NodeContent::ProgressBar { .. } => MeasureContext::ProgressBar,
            NodeContent::Separator => MeasureContext::Separator,
            NodeContent::Plot { .. } => MeasureContext::Plot,
        };

        // Get children IDs
        let children_ids: Vec<NodeId> = node.children.clone();

        // Recursively create child Taffy nodes
        let taffy_children: Vec<taffy::NodeId> = children_ids
            .iter()
            .filter_map(|&child_id| self.create_taffy_node(tree, child_id, styles))
            .collect();

        // Create this node in Taffy with context
        let taffy_node = self
            .taffy
            .new_with_children(taffy_style, &taffy_children)
            .ok()?;

        // Set the context for measurement
        self.taffy.set_node_context(taffy_node, Some(measure_context)).ok()?;

        // Store mappings
        self.node_map.insert(node_id, taffy_node);
        self.reverse_map.insert(taffy_node, node_id);

        // Store reference in UiNode
        if let Some(ui_node) = tree.get_mut(node_id) {
            ui_node.taffy_node = Some(taffy_node);
        }

        Some(taffy_node)
    }

    /// Compute layout for the tree using measure function for text
    pub fn compute_layout(&mut self, tree: &mut UiTree, root: NodeId, available_width: f32, available_height: f32) {
        if let Some(&taffy_root) = self.node_map.get(&root) {
            // Compute layout with available space and measure function
            let available_space = Size {
                width: AvailableSpace::Definite(available_width),
                height: AvailableSpace::Definite(available_height),
            };

            // Use compute_layout_with_measure for text measurement
            let text_renderer = &mut self.text_renderer;
            let result = self.taffy.compute_layout_with_measure(
                taffy_root,
                available_space,
                |known_dimensions, available_space, _node_id, node_context, _style| {
                    measure_node(known_dimensions, available_space, node_context, text_renderer)
                },
            );

            if result.is_ok() {
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

/// Default font size when none specified
const DEFAULT_FONT_SIZE: f32 = 14.0;

/// Measure function for leaf nodes (text and buttons)
fn measure_node(
    known_dimensions: Size<Option<f32>>,
    _available_space: Size<AvailableSpace>,
    node_context: Option<&mut MeasureContext>,
    text_renderer: &mut TextRenderer,
) -> Size<f32> {
    // If dimensions are already known, use them
    if let (Some(width), Some(height)) = (known_dimensions.width, known_dimensions.height) {
        return Size { width, height };
    }

    match node_context {
        Some(MeasureContext::Text { text, font_size, bold }) => {
            // Use default font size if not specified (0.0)
            let actual_font_size = if *font_size <= 0.0 { DEFAULT_FONT_SIZE } else { *font_size };
            let weight = if *bold { FontWeight::Bold } else { FontWeight::Regular };
            let (text_width, text_height) = text_renderer.measure(text, actual_font_size, weight);

            // Add some padding around text
            let padding = 4.0;
            Size {
                width: known_dimensions.width.unwrap_or(text_width + padding * 2.0),
                height: known_dimensions.height.unwrap_or(text_height + padding * 2.0),
            }
        }
        Some(MeasureContext::Button { label, font_size }) => {
            // Use default font size if not specified (0.0)
            let actual_font_size = if *font_size <= 0.0 { DEFAULT_FONT_SIZE } else { *font_size };
            let (text_width, text_height) = text_renderer.measure(label, actual_font_size, FontWeight::Regular);

            // Buttons have more padding
            let h_padding = 16.0;
            let v_padding = 8.0;
            Size {
                width: known_dimensions.width.unwrap_or(text_width + h_padding * 2.0),
                height: known_dimensions.height.unwrap_or(text_height + v_padding * 2.0),
            }
        }
        Some(MeasureContext::Container) | None => {
            // Containers don't need intrinsic measurement
            Size {
                width: known_dimensions.width.unwrap_or(0.0),
                height: known_dimensions.height.unwrap_or(0.0),
            }
        }
        Some(MeasureContext::TextInput { font_size, .. }) => {
            // Text input has minimum width, height based on font
            let actual_font_size = if *font_size <= 0.0 { DEFAULT_FONT_SIZE } else { *font_size };
            let line_height = actual_font_size * 1.4;
            Size {
                width: known_dimensions.width.unwrap_or(200.0), // Default width
                height: known_dimensions.height.unwrap_or(line_height + 16.0), // padding
            }
        }
        Some(MeasureContext::Slider) => {
            // Slider has minimum dimensions
            Size {
                width: known_dimensions.width.unwrap_or(200.0),
                height: known_dimensions.height.unwrap_or(24.0),
            }
        }
        Some(MeasureContext::Checkbox { label, font_size }) => {
            // Checkbox: checkbox square + gap + label
            let actual_font_size = if *font_size <= 0.0 { DEFAULT_FONT_SIZE } else { *font_size };
            let (text_width, text_height) = text_renderer.measure(label, actual_font_size, FontWeight::Regular);
            let checkbox_size = 18.0;
            let gap = 8.0;
            Size {
                width: known_dimensions.width.unwrap_or(checkbox_size + gap + text_width + 8.0),
                height: known_dimensions.height.unwrap_or(text_height.max(checkbox_size) + 8.0),
            }
        }
        Some(MeasureContext::ProgressBar) => {
            // Progress bar default size
            Size {
                width: known_dimensions.width.unwrap_or(200.0),
                height: known_dimensions.height.unwrap_or(8.0),
            }
        }
        Some(MeasureContext::Separator) => {
            // Separator is a thin line
            Size {
                width: known_dimensions.width.unwrap_or(0.0), // Will stretch
                height: known_dimensions.height.unwrap_or(1.0),
            }
        }
        Some(MeasureContext::Plot) => {
            // Plot has default size but can be overridden
            Size {
                width: known_dimensions.width.unwrap_or(400.0),
                height: known_dimensions.height.unwrap_or(200.0),
            }
        }
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
    fn test_text_measurement() {
        let mut tree = UiTree::new();
        let mut engine = LayoutEngine::new();
        let mut styles = HashMap::new();

        // Create a root container
        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        styles.insert(
            root,
            LayoutStyle::column()
                .with_width(400.0)
                .with_height(300.0)
                .with_align_items(AlignItems::Center),
        );

        // Add text WITHOUT explicit size - should be measured
        let text_node = tree.insert(UiNode::text("Hello World"));
        tree.add_child(root, text_node);
        // No explicit size in styles - rely on measure function
        styles.insert(text_node, LayoutStyle::default());

        // Sync and compute
        engine.sync_tree(&mut tree, root, &styles);
        engine.compute_layout(&mut tree, root, 400.0, 300.0);

        // Text should have been measured and have non-zero size
        let text = tree.get(text_node).unwrap();
        println!("Text size: {}x{}", text.layout.width, text.layout.height);
        assert!(text.layout.width > 0.0, "Text width should be measured");
        assert!(text.layout.height > 0.0, "Text height should be measured");
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

    #[test]
    fn test_flex_row_with_gap() {
        // Test that flex-row with gap works correctly
        let mut tree = UiTree::new();
        let mut engine = LayoutEngine::new();
        let mut styles = HashMap::new();

        // Root container
        let root = tree.insert(UiNode::container());
        tree.set_root(root);
        styles.insert(
            root,
            LayoutStyle::row()
                .with_width(400.0)
                .with_height(100.0)
                .with_gap(8.0)  // gap-2 = 8px
                .with_align_items(AlignItems::Center),
        );

        // Verify the style was created correctly
        let root_style = styles.get(&root).unwrap();
        assert_eq!(root_style.direction, FlexDirection::Row, "Root should be flex-row");
        assert_eq!(root_style.gap, 8.0, "Root gap should be 8");

        // Three children: label + 2 buttons (using text measurement)
        let label = tree.insert(UiNode::text("Row 1:"));
        let btn1 = tree.insert(UiNode::button(1, "Button A"));
        let btn2 = tree.insert(UiNode::button(2, "Button B"));

        tree.add_child(root, label);
        tree.add_child(root, btn1);
        tree.add_child(root, btn2);

        // No explicit sizes - rely on measure function
        styles.insert(label, LayoutStyle::default());
        styles.insert(btn1, LayoutStyle::default());
        styles.insert(btn2, LayoutStyle::default());

        // Sync and compute
        engine.sync_tree(&mut tree, root, &styles);
        engine.compute_layout(&mut tree, root, 400.0, 100.0);

        // Get layouts
        let l = tree.get(label).unwrap();
        let b1 = tree.get(btn1).unwrap();
        let b2 = tree.get(btn2).unwrap();

        println!("Label: x={}, y={}, w={}, h={}", l.layout.x, l.layout.y, l.layout.width, l.layout.height);
        println!("Btn1:  x={}, y={}, w={}, h={}", b1.layout.x, b1.layout.y, b1.layout.width, b1.layout.height);
        println!("Btn2:  x={}, y={}, w={}, h={}", b2.layout.x, b2.layout.y, b2.layout.width, b2.layout.height);

        // All should have positive widths (measured)
        assert!(l.layout.width > 0.0, "Label should have measured width");
        assert!(b1.layout.width > 0.0, "Button 1 should have measured width");
        assert!(b2.layout.width > 0.0, "Button 2 should have measured width");

        // Elements should NOT overlap - each should start after previous + gap
        let gap = 8.0;
        assert!(
            b1.layout.x >= l.layout.x + l.layout.width + gap - 1.0,
            "Button 1 should be after label with gap. Label ends at {}, btn1 starts at {}",
            l.layout.x + l.layout.width,
            b1.layout.x
        );
        assert!(
            b2.layout.x >= b1.layout.x + b1.layout.width + gap - 1.0,
            "Button 2 should be after button 1 with gap. Btn1 ends at {}, btn2 starts at {}",
            b1.layout.x + b1.layout.width,
            b2.layout.x
        );
    }

    #[test]
    fn test_simulated_soc_structure() {
        // This test simulates the exact structure from test-layout.soc
        use crate::style_parser::parse_style;
        use crate::node::NodeStyle;

        let mut tree = UiTree::new();
        let mut engine = LayoutEngine::new();
        let mut styles = HashMap::new();

        // Root container: "bg-[#1a1a1a] w-full h-full p-6 flex-col items-center gap-4"
        let root_parsed = parse_style("bg-[#1a1a1a] w-full h-full p-6 flex-col items-center gap-4").unwrap();
        let mut root_style = root_parsed.layout;
        root_style.width = Some(500.0);  // Fixed window size
        root_style.height = Some(400.0);
        let mut root_node = UiNode::container();
        root_node.style = root_parsed.visual;
        let root = tree.insert(root_node);
        tree.set_root(root);
        styles.insert(root, root_style);

        // Title: "Layout Test"
        let title_parsed = parse_style("text-white text-2xl font-bold").unwrap();
        let mut title_node = UiNode::text("Layout Test");
        title_node.style = title_parsed.visual;
        let title = tree.insert(title_node);
        tree.add_child(root, title);
        styles.insert(title, title_parsed.layout);

        // Row box: "bg-[#333333] p-4 rounded-lg flex-row gap-2 items-center"
        let row_parsed = parse_style("bg-[#333333] p-4 rounded-lg flex-row gap-2 items-center").unwrap();
        let mut row_node = UiNode::container();
        row_node.style = row_parsed.visual;
        let row_box = tree.insert(row_node);
        tree.add_child(root, row_box);
        styles.insert(row_box, row_parsed.layout.clone());

        // Verify row box has flex-row direction
        println!("Row box direction: {:?}", row_parsed.layout.direction);
        println!("Row box gap: {:?}", row_parsed.layout.gap);
        assert_eq!(row_parsed.layout.direction, FlexDirection::Row, "Row box should be flex-row");

        // Label inside row: "Row 1:"
        let label_parsed = parse_style("text-blue-400").unwrap();
        let mut label_node = UiNode::text("Row 1:");
        label_node.style = label_parsed.visual;
        let label = tree.insert(label_node);
        tree.add_child(row_box, label);
        styles.insert(label, label_parsed.layout);

        // Button A: "bg-blue-600 text-white p-2 rounded"
        let btn_a_parsed = parse_style("bg-blue-600 text-white p-2 rounded").unwrap();
        let mut btn_a_node = UiNode::button(1, "Button A");
        btn_a_node.style = btn_a_parsed.visual;
        let btn_a = tree.insert(btn_a_node);
        tree.add_child(row_box, btn_a);
        styles.insert(btn_a, btn_a_parsed.layout);

        // Button B: "bg-green-600 text-white p-2 rounded"
        let btn_b_parsed = parse_style("bg-green-600 text-white p-2 rounded").unwrap();
        let mut btn_b_node = UiNode::button(2, "Button B");
        btn_b_node.style = btn_b_parsed.visual;
        let btn_b = tree.insert(btn_b_node);
        tree.add_child(row_box, btn_b);
        styles.insert(btn_b, btn_b_parsed.layout);

        // Compute layout
        engine.sync_tree(&mut tree, root, &styles);
        engine.compute_layout(&mut tree, root, 500.0, 400.0);

        // Get layouts
        let l = tree.get(label).unwrap();
        let ba = tree.get(btn_a).unwrap();
        let bb = tree.get(btn_b).unwrap();
        let row = tree.get(row_box).unwrap();

        println!("\n=== SOC Simulation Test ===");
        println!("Row box: x={}, y={}, w={}, h={}", row.layout.x, row.layout.y, row.layout.width, row.layout.height);
        println!("Label: x={}, y={}, w={}, h={}", l.layout.x, l.layout.y, l.layout.width, l.layout.height);
        println!("BtnA:  x={}, y={}, w={}, h={}", ba.layout.x, ba.layout.y, ba.layout.width, ba.layout.height);
        println!("BtnB:  x={}, y={}, w={}, h={}", bb.layout.x, bb.layout.y, bb.layout.width, bb.layout.height);

        // Check that buttons don't overlap
        // BtnA should start after label + gap
        assert!(
            ba.layout.x > l.layout.x + l.layout.width,
            "Button A should be after label. Label ends at {}, BtnA starts at {}",
            l.layout.x + l.layout.width,
            ba.layout.x
        );

        // BtnB should start after BtnA + gap
        assert!(
            bb.layout.x > ba.layout.x + ba.layout.width,
            "Button B should be after Button A. BtnA ends at {}, BtnB starts at {}",
            ba.layout.x + ba.layout.width,
            bb.layout.x
        );
    }
}
