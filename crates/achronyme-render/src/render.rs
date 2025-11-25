//! Software Renderer - CPU-based pixel rendering
//!
//! This module provides basic 2D rendering primitives using softbuffer.
//! It's designed to be simple and correct first, with GPU acceleration as a future upgrade.

use crate::node::{NodeContent, NodeId, UiTree};

/// Color represented as ARGB (0xAARRGGBB)
pub type Color = u32;

/// A simple software renderer that draws to a pixel buffer
pub struct SoftwareRenderer {
    /// Width of the render target
    width: u32,
    /// Height of the render target
    height: u32,
}

impl SoftwareRenderer {
    /// Create a new renderer for the given dimensions
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// Resize the renderer
    pub fn resize(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Render the entire UI tree to the buffer
    pub fn render(&self, buffer: &mut [u32], tree: &UiTree, root: NodeId) {
        // Clear with dark background
        self.fill_rect(buffer, 0, 0, self.width, self.height, 0xFF1A1A1A);

        // Render tree recursively
        self.render_node(buffer, tree, root);
    }

    fn render_node(&self, buffer: &mut [u32], tree: &UiTree, node_id: NodeId) {
        let node = match tree.get(node_id) {
            Some(n) => n,
            None => return,
        };

        let layout = &node.layout;
        let style = &node.style;

        let x = layout.x as i32;
        let y = layout.y as i32;
        let w = layout.width as u32;
        let h = layout.height as u32;

        // Draw background if set
        if let Some(bg) = style.background_color {
            if style.border_radius > 0.0 {
                self.fill_rounded_rect(buffer, x, y, w, h, style.border_radius, bg);
            } else {
                self.fill_rect(buffer, x as u32, y as u32, w, h, bg);
            }
        }

        // Draw border if set
        if let Some(border_color) = style.border_color {
            if style.border_width > 0.0 {
                self.stroke_rect(buffer, x, y, w, h, style.border_width as u32, border_color);
            }
        }

        // Draw content based on type
        match &node.content {
            NodeContent::Container => {
                // Containers just provide layout, children handle their own rendering
            }
            NodeContent::Text(text) => {
                // Simple text rendering (placeholder - real text needs font rendering)
                let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
                self.draw_text_placeholder(buffer, x, y, w, h, text, text_color);
            }
            NodeContent::Button { label } => {
                // Button background already drawn above
                let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
                self.draw_text_placeholder(buffer, x, y, w, h, label, text_color);
            }
        }

        // Render children
        for &child_id in &node.children {
            self.render_node(buffer, tree, child_id);
        }
    }

    /// Fill a rectangle with a solid color
    pub fn fill_rect(&self, buffer: &mut [u32], x: u32, y: u32, w: u32, h: u32, color: Color) {
        for py in y..(y + h).min(self.height) {
            for px in x..(x + w).min(self.width) {
                let idx = (py * self.width + px) as usize;
                if idx < buffer.len() {
                    buffer[idx] = self.blend_color(buffer[idx], color);
                }
            }
        }
    }

    /// Fill a rounded rectangle
    pub fn fill_rounded_rect(
        &self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        radius: f32,
        color: Color,
    ) {
        let r = radius.min(w as f32 / 2.0).min(h as f32 / 2.0);
        let ri = r as i32;

        for py in 0..h as i32 {
            for px in 0..w as i32 {
                let screen_x = x + px;
                let screen_y = y + py;

                if screen_x < 0 || screen_y < 0 {
                    continue;
                }
                if screen_x >= self.width as i32 || screen_y >= self.height as i32 {
                    continue;
                }

                // Check if pixel is inside rounded corners
                let in_rect = self.point_in_rounded_rect(px, py, w as i32, h as i32, ri);
                if in_rect {
                    let idx = (screen_y as u32 * self.width + screen_x as u32) as usize;
                    if idx < buffer.len() {
                        buffer[idx] = self.blend_color(buffer[idx], color);
                    }
                }
            }
        }
    }

    fn point_in_rounded_rect(&self, px: i32, py: i32, w: i32, h: i32, r: i32) -> bool {
        // Check corners
        if px < r && py < r {
            // Top-left corner
            let dx = r - px;
            let dy = r - py;
            return dx * dx + dy * dy <= r * r;
        }
        if px >= w - r && py < r {
            // Top-right corner
            let dx = px - (w - r - 1);
            let dy = r - py;
            return dx * dx + dy * dy <= r * r;
        }
        if px < r && py >= h - r {
            // Bottom-left corner
            let dx = r - px;
            let dy = py - (h - r - 1);
            return dx * dx + dy * dy <= r * r;
        }
        if px >= w - r && py >= h - r {
            // Bottom-right corner
            let dx = px - (w - r - 1);
            let dy = py - (h - r - 1);
            return dx * dx + dy * dy <= r * r;
        }
        true
    }

    /// Stroke (outline) a rectangle
    pub fn stroke_rect(
        &self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        thickness: u32,
        color: Color,
    ) {
        let x = x.max(0) as u32;
        let y = y.max(0) as u32;

        // Top edge
        self.fill_rect(buffer, x, y, w, thickness, color);
        // Bottom edge
        if h > thickness {
            self.fill_rect(buffer, x, y + h - thickness, w, thickness, color);
        }
        // Left edge
        self.fill_rect(buffer, x, y, thickness, h, color);
        // Right edge
        if w > thickness {
            self.fill_rect(buffer, x + w - thickness, y, thickness, h, color);
        }
    }

    /// Simple text placeholder (draws a colored bar where text would be)
    /// Real text rendering requires font rasterization (cosmic-text or similar)
    fn draw_text_placeholder(
        &self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        _text: &str,
        color: Color,
    ) {
        // For now, draw a small indicator bar
        // Real implementation would use cosmic-text for proper glyph rendering
        let bar_height = 2u32;
        let bar_y = y + (h as i32 / 2);
        let bar_w = (w as f32 * 0.6) as u32;
        let bar_x = x + ((w - bar_w) / 2) as i32;

        if bar_x >= 0 && bar_y >= 0 {
            self.fill_rect(buffer, bar_x as u32, bar_y as u32, bar_w, bar_height, color);
        }
    }

    /// Blend a source color over a destination color (simple alpha blend)
    fn blend_color(&self, dst: Color, src: Color) -> Color {
        let src_a = ((src >> 24) & 0xFF) as f32 / 255.0;

        if src_a >= 1.0 {
            return src;
        }
        if src_a <= 0.0 {
            return dst;
        }

        let src_r = ((src >> 16) & 0xFF) as f32;
        let src_g = ((src >> 8) & 0xFF) as f32;
        let src_b = (src & 0xFF) as f32;

        let dst_r = ((dst >> 16) & 0xFF) as f32;
        let dst_g = ((dst >> 8) & 0xFF) as f32;
        let dst_b = (dst & 0xFF) as f32;

        let out_r = (src_r * src_a + dst_r * (1.0 - src_a)) as u32;
        let out_g = (src_g * src_a + dst_g * (1.0 - src_a)) as u32;
        let out_b = (src_b * src_a + dst_b * (1.0 - src_a)) as u32;

        0xFF000000 | (out_r << 16) | (out_g << 8) | out_b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::UiNode;

    #[test]
    fn test_fill_rect() {
        let renderer = SoftwareRenderer::new(100, 100);
        let mut buffer = vec![0xFF000000; 10000];

        renderer.fill_rect(&mut buffer, 10, 10, 20, 20, 0xFFFF0000);

        // Check a pixel inside the rect
        let idx = 15 * 100 + 15;
        assert_eq!(buffer[idx], 0xFFFF0000);

        // Check a pixel outside
        let idx_outside = 5 * 100 + 5;
        assert_eq!(buffer[idx_outside], 0xFF000000);
    }

    #[test]
    fn test_render_tree() {
        let renderer = SoftwareRenderer::new(200, 200);
        let mut buffer = vec![0xFF000000; 40000];

        let mut tree = UiTree::new();
        let root = tree.insert(UiNode::container().with_background(0xFF333333));
        tree.set_root(root);

        // Set layout manually for test
        if let Some(node) = tree.get_mut(root) {
            node.layout.x = 10.0;
            node.layout.y = 10.0;
            node.layout.width = 100.0;
            node.layout.height = 50.0;
        }

        renderer.render(&mut buffer, &tree, root);

        // Check that the background was drawn
        let idx = 30 * 200 + 30; // Inside the rect
        assert_eq!(buffer[idx], 0xFF333333);
    }
}
