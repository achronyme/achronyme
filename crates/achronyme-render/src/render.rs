//! Software Renderer - CPU-based pixel rendering
//!
//! This module provides basic 2D rendering primitives using softbuffer.
//! It's designed to be simple and correct first, with GPU acceleration as a future upgrade.

use crate::node::{NodeContent, NodeId, NodeStyle, PlotKind, PlotSeries, UiTree};
use crate::text::{FontWeight, TextAlign, TextRenderer};

/// Color represented as ARGB (0xAARRGGBB)
pub type Color = u32;

/// Interactive state passed to renderer
#[derive(Default, Clone, Copy)]
pub struct RenderState {
    /// Currently hovered node
    pub hovered: Option<NodeId>,
    /// Currently pressed node
    pub pressed: Option<NodeId>,
}

/// A simple software renderer that draws to a pixel buffer
pub struct SoftwareRenderer {
    /// Width of the render target
    width: u32,
    /// Height of the render target
    height: u32,
    /// Text renderer for font rasterization
    text_renderer: TextRenderer,
}

impl SoftwareRenderer {
    /// Create a new renderer for the given dimensions
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            text_renderer: TextRenderer::new(),
        }
    }

    /// Resize the renderer
    pub fn resize(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Render the entire UI tree to the buffer
    pub fn render(&mut self, buffer: &mut [u32], tree: &UiTree, root: NodeId) {
        self.render_with_state(buffer, tree, root, RenderState::default());
    }

    /// Render with interactive state (hover/pressed tracking)
    pub fn render_with_state(
        &mut self,
        buffer: &mut [u32],
        tree: &UiTree,
        root: NodeId,
        state: RenderState,
    ) {
        // Clear with dark background
        Self::fill_rect_static(buffer, self.width, self.height, 0, 0, self.width, self.height, 0xFF1A1A1A);

        // Render tree recursively
        self.render_node_with_state(buffer, tree, root, &state);
    }

    fn render_node_with_state(
        &mut self,
        buffer: &mut [u32],
        tree: &UiTree,
        node_id: NodeId,
        state: &RenderState,
    ) {
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

        // Determine interactive state
        let is_hovered = state.hovered == Some(node_id);
        let is_pressed = state.pressed == Some(node_id);

        // Draw background if set, with hover/press effects
        if let Some(bg) = style.background_color {
            let bg = if is_pressed {
                self.darken_color(bg, 0.2)
            } else if is_hovered {
                self.lighten_color(bg, 0.15)
            } else {
                bg
            };

            if style.border_radius > 0.0 {
                self.fill_rounded_rect(buffer, x, y, w, h, style.border_radius, bg);
            } else {
                self.fill_rect(buffer, x as u32, y as u32, w, h, bg);
            }
        }

        // Draw hover outline for interactive elements
        if is_hovered && matches!(node.content, NodeContent::Button { .. }) {
            let outline_color = 0x40FFFFFF; // Semi-transparent white
            self.stroke_rect(buffer, x, y, w, h, 2, outline_color);
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
                let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
                let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
                let weight = if style.font_bold { FontWeight::Bold } else { FontWeight::Regular };
                let align = match style.text_align.as_deref() {
                    Some("center") => TextAlign::Center,
                    Some("right") => TextAlign::Right,
                    _ => TextAlign::Left,
                };
                self.text_renderer.render(
                    buffer,
                    self.width,
                    self.height,
                    x,
                    y,
                    w,
                    h,
                    text,
                    font_size,
                    text_color,
                    align,
                    weight,
                );
            }
            NodeContent::Button { label } => {
                // Button background already drawn above
                let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
                let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
                let weight = if style.font_bold { FontWeight::Bold } else { FontWeight::Regular };
                self.text_renderer.render(
                    buffer,
                    self.width,
                    self.height,
                    x,
                    y,
                    w,
                    h,
                    label,
                    font_size,
                    text_color,
                    TextAlign::Center,
                    weight,
                );
            }
            NodeContent::TextInput { id, placeholder } => {
                self.render_text_input(buffer, x, y, w, h, *id, placeholder, style, is_hovered);
            }
            NodeContent::Slider { id, min, max, value } => {
                self.render_slider(buffer, x, y, w, h, *id, *min, *max, *value, style, is_hovered);
            }
            NodeContent::Checkbox { id, label, checked } => {
                self.render_checkbox(buffer, x, y, w, h, *id, label, *checked, style, is_hovered);
            }
            NodeContent::ProgressBar { progress } => {
                self.render_progress_bar(buffer, x, y, w, h, *progress, style);
            }
            NodeContent::Separator => {
                self.render_separator(buffer, x, y, w, h, style);
            }
            NodeContent::Plot { title, x_label, y_label, series } => {
                self.render_plot(buffer, x, y, w, h, title, x_label, y_label, series, style);
            }
        }

        // Render children with same state
        for &child_id in &node.children {
            self.render_node_with_state(buffer, tree, child_id, state);
        }
    }

    /// Lighten a color by a factor (0.0 - 1.0)
    fn lighten_color(&self, color: Color, factor: f32) -> Color {
        let a = (color >> 24) & 0xFF;
        let r = ((color >> 16) & 0xFF) as f32;
        let g = ((color >> 8) & 0xFF) as f32;
        let b = (color & 0xFF) as f32;

        let r = (r + (255.0 - r) * factor).min(255.0) as u32;
        let g = (g + (255.0 - g) * factor).min(255.0) as u32;
        let b = (b + (255.0 - b) * factor).min(255.0) as u32;

        (a << 24) | (r << 16) | (g << 8) | b
    }

    /// Darken a color by a factor (0.0 - 1.0)
    fn darken_color(&self, color: Color, factor: f32) -> Color {
        let a = (color >> 24) & 0xFF;
        let r = ((color >> 16) & 0xFF) as f32;
        let g = ((color >> 8) & 0xFF) as f32;
        let b = (color & 0xFF) as f32;

        let r = (r * (1.0 - factor)).max(0.0) as u32;
        let g = (g * (1.0 - factor)).max(0.0) as u32;
        let b = (b * (1.0 - factor)).max(0.0) as u32;

        (a << 24) | (r << 16) | (g << 8) | b
    }

    /// Fill a rectangle with a solid color (static version for use when self is borrowed)
    fn fill_rect_static(
        buffer: &mut [u32],
        buf_width: u32,
        buf_height: u32,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        color: Color,
    ) {
        for py in y..(y + h).min(buf_height) {
            for px in x..(x + w).min(buf_width) {
                let idx = (py * buf_width + px) as usize;
                if idx < buffer.len() {
                    buffer[idx] = Self::blend_color_static(buffer[idx], color);
                }
            }
        }
    }

    /// Fill a rectangle with a solid color
    pub fn fill_rect(&self, buffer: &mut [u32], x: u32, y: u32, w: u32, h: u32, color: Color) {
        Self::fill_rect_static(buffer, self.width, self.height, x, y, w, h, color);
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

    /// Blend a source color over a destination color (simple alpha blend) - static version
    fn blend_color_static(dst: Color, src: Color) -> Color {
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

    /// Blend a source color over a destination color (simple alpha blend)
    fn blend_color(&self, dst: Color, src: Color) -> Color {
        Self::blend_color_static(dst, src)
    }

    // ===== Widget Rendering Methods =====

    /// Render a text input field
    fn render_text_input(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        _id: u64,
        placeholder: &str,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        // Background
        let bg_color = style.background_color.unwrap_or(0xFF2D2D2D);
        let bg_color = if is_hovered { self.lighten_color(bg_color, 0.1) } else { bg_color };
        if style.border_radius > 0.0 {
            self.fill_rounded_rect(buffer, x, y, w, h, style.border_radius, bg_color);
        } else {
            self.fill_rect(buffer, x as u32, y as u32, w, h, bg_color);
        }

        // Border
        let border_color = if is_hovered { 0xFF60A5FA } else { style.border_color.unwrap_or(0xFF4B5563) };
        self.stroke_rect(buffer, x, y, w, h, 1, border_color);

        // Placeholder text (grey, left-aligned with padding)
        let text_color = 0xFF9CA3AF; // Grey for placeholder
        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
        let padding = 8;
        self.text_renderer.render(
            buffer,
            self.width,
            self.height,
            x + padding,
            y,
            w.saturating_sub(padding as u32 * 2),
            h,
            placeholder,
            font_size,
            text_color,
            TextAlign::Left,
            FontWeight::Regular,
        );
    }

    /// Render a slider control
    fn render_slider(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        _id: u64,
        min: f64,
        max: f64,
        value: f64,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        let track_height = 6u32;
        let track_y = y + (h as i32 - track_height as i32) / 2;

        // Track background
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        self.fill_rounded_rect(buffer, x, track_y, w, track_height, 3.0, track_bg);

        // Calculate fill width based on value
        let range = max - min;
        let normalized = if range > 0.0 { ((value - min) / range).clamp(0.0, 1.0) } else { 0.0 };
        let fill_width = ((w as f64) * normalized) as u32;

        // Filled portion (blue)
        let fill_color = 0xFF3B82F6;
        if fill_width > 0 {
            self.fill_rounded_rect(buffer, x, track_y, fill_width, track_height, 3.0, fill_color);
        }

        // Thumb (circle)
        let thumb_radius = 8i32;
        let thumb_x = x + fill_width as i32;
        let thumb_y = y + h as i32 / 2;
        let thumb_color = if is_hovered { 0xFFFFFFFF } else { 0xFFE5E7EB };
        self.fill_circle(buffer, thumb_x, thumb_y, thumb_radius, thumb_color);
    }

    /// Render a checkbox
    fn render_checkbox(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        _id: u64,
        label: &str,
        checked: bool,
        style: &NodeStyle,
        is_hovered: bool,
    ) {
        let box_size = 18i32;
        let box_y = y + (h as i32 - box_size) / 2;

        // Checkbox box
        let box_bg = if checked { 0xFF3B82F6 } else { 0xFF374151 };
        let box_bg = if is_hovered { self.lighten_color(box_bg, 0.15) } else { box_bg };
        self.fill_rounded_rect(buffer, x, box_y, box_size as u32, box_size as u32, 4.0, box_bg);

        // Checkmark if checked
        if checked {
            // Simple checkmark using lines
            let cx = x + box_size / 2;
            let cy = box_y + box_size / 2;
            // Draw a simple "✓" shape
            self.draw_line(buffer, cx - 4, cy, cx - 1, cy + 3, 0xFFFFFFFF);
            self.draw_line(buffer, cx - 1, cy + 3, cx + 5, cy - 4, 0xFFFFFFFF);
        }

        // Border
        let border_color = if is_hovered { 0xFF60A5FA } else { 0xFF4B5563 };
        self.stroke_rect(buffer, x, box_y, box_size as u32, box_size as u32, 1, border_color);

        // Label text
        let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
        let font_size = if style.font_size > 0.0 { style.font_size } else { 14.0 };
        let label_x = x + box_size + 8;
        self.text_renderer.render(
            buffer,
            self.width,
            self.height,
            label_x,
            y,
            w.saturating_sub((box_size + 8) as u32),
            h,
            label,
            font_size,
            text_color,
            TextAlign::Left,
            FontWeight::Regular,
        );
    }

    /// Render a progress bar
    fn render_progress_bar(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        progress: f32,
        style: &NodeStyle,
    ) {
        // Track background
        let track_bg = style.background_color.unwrap_or(0xFF374151);
        let radius = style.border_radius.min(h as f32 / 2.0);
        self.fill_rounded_rect(buffer, x, y, w, h, radius, track_bg);

        // Filled portion
        let fill_width = ((w as f32) * progress.clamp(0.0, 1.0)) as u32;
        if fill_width > 0 {
            let fill_color = 0xFF3B82F6; // Blue
            self.fill_rounded_rect(buffer, x, y, fill_width, h, radius, fill_color);
        }
    }

    /// Render a separator line
    fn render_separator(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        style: &NodeStyle,
    ) {
        let color = style.background_color.unwrap_or(0xFF4B5563);
        self.fill_rect(buffer, x as u32, y as u32, w, h.max(1), color);
    }

    /// Render a plot/chart
    fn render_plot(
        &mut self,
        buffer: &mut [u32],
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        title: &str,
        _x_label: &str,
        _y_label: &str,
        series: &[PlotSeries],
        style: &NodeStyle,
    ) {
        // Background
        let bg_color = style.background_color.unwrap_or(0xFF1F2937);
        let radius = style.border_radius;
        self.fill_rounded_rect(buffer, x, y, w, h, radius, bg_color);

        // Title
        let title_height = 24i32;
        let text_color = style.text_color.unwrap_or(0xFFFFFFFF);
        self.text_renderer.render(
            buffer,
            self.width,
            self.height,
            x + 8,
            y + 4,
            w - 16,
            title_height as u32,
            title,
            14.0,
            text_color,
            TextAlign::Left,
            FontWeight::Bold,
        );

        // Plot area
        let plot_x = x + 40;
        let plot_y = y + title_height + 8;
        let plot_w = w.saturating_sub(50) as i32;
        let plot_h = h.saturating_sub(title_height as u32 + 24) as i32;

        if plot_w <= 0 || plot_h <= 0 || series.is_empty() {
            return;
        }

        // Find data bounds
        let mut min_x = f64::MAX;
        let mut max_x = f64::MIN;
        let mut min_y = f64::MAX;
        let mut max_y = f64::MIN;

        for s in series {
            for &(px, py) in &s.data {
                if px < min_x { min_x = px; }
                if px > max_x { max_x = px; }
                if py < min_y { min_y = py; }
                if py > max_y { max_y = py; }
            }
        }

        // Add padding to bounds
        let range_x = (max_x - min_x).max(0.001);
        let range_y = (max_y - min_y).max(0.001);

        // Draw grid lines
        let grid_color = 0xFF374151;
        for i in 0..=4 {
            let gy = plot_y + (plot_h * i) / 4;
            self.draw_line(buffer, plot_x, gy, plot_x + plot_w, gy, grid_color);
        }

        // Draw each series
        for s in series {
            if s.data.len() < 2 {
                continue;
            }

            let color = s.color;

            match s.kind {
                PlotKind::Line => {
                    // Draw connected lines
                    for i in 1..s.data.len() {
                        let (x1, y1) = s.data[i - 1];
                        let (x2, y2) = s.data[i];

                        let sx1 = plot_x + ((x1 - min_x) / range_x * plot_w as f64) as i32;
                        let sy1 = plot_y + plot_h - ((y1 - min_y) / range_y * plot_h as f64) as i32;
                        let sx2 = plot_x + ((x2 - min_x) / range_x * plot_w as f64) as i32;
                        let sy2 = plot_y + plot_h - ((y2 - min_y) / range_y * plot_h as f64) as i32;

                        self.draw_line(buffer, sx1, sy1, sx2, sy2, color);
                    }
                }
                PlotKind::Scatter => {
                    // Draw points
                    let radius = s.radius.max(1.0) as i32;
                    for &(px, py) in &s.data {
                        let sx = plot_x + ((px - min_x) / range_x * plot_w as f64) as i32;
                        let sy = plot_y + plot_h - ((py - min_y) / range_y * plot_h as f64) as i32;
                        self.fill_circle(buffer, sx, sy, radius, color);
                    }
                }
            }
        }

        // Border around plot area
        self.stroke_rect(buffer, plot_x, plot_y, plot_w as u32, plot_h as u32, 1, 0xFF4B5563);
    }

    /// Draw a filled circle
    fn fill_circle(&self, buffer: &mut [u32], cx: i32, cy: i32, radius: i32, color: Color) {
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= radius * radius {
                    let px = cx + dx;
                    let py = cy + dy;
                    if px >= 0 && py >= 0 && px < self.width as i32 && py < self.height as i32 {
                        let idx = (py as u32 * self.width + px as u32) as usize;
                        if idx < buffer.len() {
                            buffer[idx] = self.blend_color(buffer[idx], color);
                        }
                    }
                }
            }
        }
    }

    /// Draw a line using Bresenham's algorithm
    fn draw_line(&self, buffer: &mut [u32], x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x0;
        let mut y = y0;

        loop {
            if x >= 0 && y >= 0 && x < self.width as i32 && y < self.height as i32 {
                let idx = (y as u32 * self.width + x as u32) as usize;
                if idx < buffer.len() {
                    buffer[idx] = self.blend_color(buffer[idx], color);
                }
            }

            if x == x1 && y == y1 {
                break;
            }

            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
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
        let mut renderer = SoftwareRenderer::new(200, 200);
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
