//! Text Rendering Module
//!
//! Provides font loading and text rasterization using fontdue.
//! Includes an embedded default font (Inter) for zero-config usage.

use fontdue::{Font, FontSettings};
use std::collections::HashMap;

/// Embedded Inter font (Regular weight)
/// Inter is an open-source font designed for computer screens
/// License: SIL Open Font License 1.1
const INTER_REGULAR: &[u8] = include_bytes!("../assets/Inter-Regular.ttf");

/// Text alignment options
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TextAlign {
    #[default]
    Left,
    Center,
    Right,
}

/// Font weight (simplified)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FontWeight {
    #[default]
    Regular,
    Bold,
}

/// Manages fonts and text rendering
pub struct TextRenderer {
    /// Regular font
    font_regular: Font,
    /// Bold font (same as regular for now, until we add bold variant)
    font_bold: Font,
    /// Glyph cache: (char, size_px) -> (bitmap, metrics)
    cache: HashMap<(char, u16), CachedGlyph>,
}

/// A cached glyph bitmap
struct CachedGlyph {
    /// Grayscale bitmap (alpha values)
    bitmap: Vec<u8>,
    /// Width of the glyph bitmap
    width: u32,
    /// Height of the glyph bitmap
    height: u32,
    /// Horizontal offset from cursor
    xmin: i32,
    /// Vertical offset from baseline
    ymin: i32,
    /// How much to advance cursor after this glyph
    advance: f32,
}

impl TextRenderer {
    /// Create a new text renderer with embedded fonts
    pub fn new() -> Self {
        let font_regular = Font::from_bytes(INTER_REGULAR, FontSettings::default())
            .expect("Failed to load embedded font");
        let font_bold = font_regular.clone();

        Self {
            font_regular,
            font_bold,
            cache: HashMap::new(),
        }
    }

    /// Measure text dimensions without rendering
    pub fn measure(&mut self, text: &str, size: f32, _weight: FontWeight) -> (f32, f32) {
        let font = &self.font_regular;
        let mut width = 0.0f32;
        let mut max_height = 0.0f32;

        for c in text.chars() {
            let metrics = font.metrics(c, size);
            width += metrics.advance_width;
            max_height = max_height.max(size);
        }

        (width, max_height)
    }

    /// Render text to a pixel buffer
    ///
    /// # Arguments
    /// * `buffer` - Target pixel buffer (ARGB format)
    /// * `buffer_width` - Width of the buffer in pixels
    /// * `buffer_height` - Height of the buffer in pixels
    /// * `x` - Left position
    /// * `y` - Top position (text baseline will be offset from this)
    /// * `max_width` - Maximum width for text (for alignment)
    /// * `max_height` - Maximum height for text (for vertical centering)
    /// * `text` - Text string to render
    /// * `size` - Font size in pixels
    /// * `color` - Text color (ARGB)
    /// * `align` - Text alignment within max_width
    /// * `weight` - Font weight
    pub fn render(
        &mut self,
        buffer: &mut [u32],
        buffer_width: u32,
        buffer_height: u32,
        x: i32,
        y: i32,
        max_width: u32,
        max_height: u32,
        text: &str,
        size: f32,
        color: u32,
        align: TextAlign,
        weight: FontWeight,
    ) {
        // Measure text width for alignment
        let (text_width, _) = self.measure(text, size, weight);

        // Calculate starting x based on alignment
        let start_x = match align {
            TextAlign::Left => x as f32,
            TextAlign::Center => x as f32 + (max_width as f32 - text_width) / 2.0,
            TextAlign::Right => x as f32 + max_width as f32 - text_width,
        };

        // Vertical centering within max_height
        let baseline_y = y as f32 + (max_height as f32 + size * 0.7) / 2.0;

        let mut cursor_x = start_x;
        let size_key = (size * 10.0) as u16; // Cache key precision

        for c in text.chars() {
            // Check cache or rasterize
            let glyph = self.get_or_rasterize(weight, c, size, size_key);

            // Calculate position
            let gx = (cursor_x + glyph.xmin as f32) as i32;
            let gy = (baseline_y - glyph.ymin as f32 - glyph.height as f32) as i32;

            // Blit glyph to buffer
            Self::blit_glyph(
                buffer,
                buffer_width,
                buffer_height,
                gx,
                gy,
                &glyph.bitmap,
                glyph.width,
                glyph.height,
                color,
            );

            cursor_x += glyph.advance;
        }
    }

    fn get_or_rasterize(&mut self, weight: FontWeight, c: char, size: f32, size_key: u16) -> CachedGlyph {
        let cache_key = (c, size_key);

        if let Some(cached) = self.cache.get(&cache_key) {
            return CachedGlyph {
                bitmap: cached.bitmap.clone(),
                width: cached.width,
                height: cached.height,
                xmin: cached.xmin,
                ymin: cached.ymin,
                advance: cached.advance,
            };
        }

        // Select font based on weight
        let font = match weight {
            FontWeight::Regular => &self.font_regular,
            FontWeight::Bold => &self.font_bold,
        };

        // Rasterize the glyph
        let (metrics, bitmap) = font.rasterize(c, size);

        let glyph = CachedGlyph {
            bitmap,
            width: metrics.width as u32,
            height: metrics.height as u32,
            xmin: metrics.xmin,
            ymin: metrics.ymin,
            advance: metrics.advance_width,
        };

        // Store in cache
        self.cache.insert(cache_key, CachedGlyph {
            bitmap: glyph.bitmap.clone(),
            width: glyph.width,
            height: glyph.height,
            xmin: glyph.xmin,
            ymin: glyph.ymin,
            advance: glyph.advance,
        });

        glyph
    }

    fn blit_glyph(
        buffer: &mut [u32],
        buffer_width: u32,
        buffer_height: u32,
        x: i32,
        y: i32,
        glyph_bitmap: &[u8],
        glyph_width: u32,
        glyph_height: u32,
        color: u32,
    ) {
        let color_r = ((color >> 16) & 0xFF) as f32;
        let color_g = ((color >> 8) & 0xFF) as f32;
        let color_b = (color & 0xFF) as f32;

        for gy in 0..glyph_height {
            for gx in 0..glyph_width {
                let px = x + gx as i32;
                let py = y + gy as i32;

                // Bounds check
                if px < 0 || py < 0 || px >= buffer_width as i32 || py >= buffer_height as i32 {
                    continue;
                }

                let glyph_idx = (gy * glyph_width + gx) as usize;
                let alpha = glyph_bitmap.get(glyph_idx).copied().unwrap_or(0) as f32 / 255.0;

                if alpha < 0.01 {
                    continue;
                }

                let buffer_idx = (py as u32 * buffer_width + px as u32) as usize;
                if buffer_idx >= buffer.len() {
                    continue;
                }

                // Alpha blend with existing pixel
                let dst = buffer[buffer_idx];
                let dst_r = ((dst >> 16) & 0xFF) as f32;
                let dst_g = ((dst >> 8) & 0xFF) as f32;
                let dst_b = (dst & 0xFF) as f32;

                let out_r = (color_r * alpha + dst_r * (1.0 - alpha)) as u32;
                let out_g = (color_g * alpha + dst_g * (1.0 - alpha)) as u32;
                let out_b = (color_b * alpha + dst_b * (1.0 - alpha)) as u32;

                buffer[buffer_idx] = 0xFF000000 | (out_r << 16) | (out_g << 8) | out_b;
            }
        }
    }
}

impl Default for TextRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_renderer_creation() {
        let renderer = TextRenderer::new();
        assert!(renderer.cache.is_empty());
    }

    #[test]
    fn test_measure_text() {
        let mut renderer = TextRenderer::new();
        let (width, height) = renderer.measure("Hello", 16.0, FontWeight::Regular);
        assert!(width > 0.0);
        assert!(height > 0.0);
    }

    #[test]
    fn test_render_text() {
        let mut renderer = TextRenderer::new();
        let mut buffer = vec![0xFF000000u32; 100 * 30];

        renderer.render(
            &mut buffer,
            100,
            30,
            5,
            5,
            90,
            20,
            "Test",
            14.0,
            0xFFFFFFFF,
            TextAlign::Left,
            FontWeight::Regular,
        );

        // Check that some pixels were modified
        let white_pixels = buffer.iter().filter(|&&p| p != 0xFF000000).count();
        assert!(white_pixels > 0, "Text should have rendered some pixels");
    }
}
