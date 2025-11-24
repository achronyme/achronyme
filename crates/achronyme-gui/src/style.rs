use achronyme_types::value::Value;
use egui::{Color32, Margin, Rounding, Stroke};

/// Represents a parsed style configuration from an Achronyme string.
/// Example: "bg-gray-900 p-4 rounded-lg border-red-500"
#[derive(Default, Clone, Debug)]
pub struct StyleConfig {
    pub background_color: Option<Color32>,
    pub rounding: Rounding,
    pub border: Stroke,
    pub margin: Margin,
    pub padding: Margin,
    pub text_color: Option<Color32>,
    pub height: Option<f32>,
    pub width: Option<f32>,
    pub layout_mode: LayoutMode,
    // New Typography fields
    pub font_size: Option<f32>,
    pub font_bold: bool,
    pub font_monospace: bool,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub enum LayoutMode {
    #[default]
    Vertical, // flex-col
    Horizontal, // flex-row
}

impl StyleConfig {
    /// Parses a generic Value (String or Record) into a StyleConfig.
    /// Prioritizes String parsing ("bg-red-500").
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::String(s) => Self::parse_tailwind(s),
            _ => Self::default(),
        }
    }

    /// The core parser engine.
    /// Transforms "bg-red-500 p-4" -> StyleConfig
    pub fn parse_tailwind(style_str: &str) -> Self {
        let mut config = Self::default();

        // Default font size (base)
        config.font_size = Some(14.0);

        for token in style_str.split_whitespace() {
            config.apply_token(token);
        }

        config
    }

    fn apply_token(&mut self, token: &str) {
        // Padding
        if let Some(val) = token.strip_prefix("p-") {
            self.padding = Margin::same(parse_size(val));
        } else if let Some(val) = token.strip_prefix("px-") {
            let s = parse_size(val);
            self.padding.left = s;
            self.padding.right = s;
        } else if let Some(val) = token.strip_prefix("py-") {
            let s = parse_size(val);
            self.padding.top = s;
            self.padding.bottom = s;
        } else if let Some(val) = token.strip_prefix("pt-") {
            self.padding.top = parse_size(val);
        } else if let Some(val) = token.strip_prefix("pb-") {
            self.padding.bottom = parse_size(val);
        } else if let Some(val) = token.strip_prefix("pl-") {
            self.padding.left = parse_size(val);
        } else if let Some(val) = token.strip_prefix("pr-") {
            self.padding.right = parse_size(val);
        }
        // Margin
        else if let Some(val) = token.strip_prefix("m-") {
            self.margin = Margin::same(parse_size(val));
        } else if let Some(val) = token.strip_prefix("mt-") {
            self.margin.top = parse_size(val);
        } else if let Some(val) = token.strip_prefix("mb-") {
            self.margin.bottom = parse_size(val);
        } else if let Some(val) = token.strip_prefix("ml-") {
            self.margin.left = parse_size(val);
        } else if let Some(val) = token.strip_prefix("mr-") {
            self.margin.right = parse_size(val);
        }
        // Colors (Background)
        else if let Some(val) = token.strip_prefix("bg-") {
            self.background_color = Some(parse_tailwind_color(val));
        }
        // Colors (Text)
        else if let Some(val) = token.strip_prefix("text-") {
            // Check if it's a size or color
            match val {
                "xs" => self.font_size = Some(10.0),
                "sm" => self.font_size = Some(12.0),
                "base" => self.font_size = Some(14.0),
                "lg" => self.font_size = Some(18.0),
                "xl" => self.font_size = Some(20.0),
                "2xl" => self.font_size = Some(24.0),
                "3xl" => self.font_size = Some(30.0),
                "4xl" => self.font_size = Some(36.0),
                _ => self.text_color = Some(parse_tailwind_color(val)),
            }
        }
        // Font Weight / Style
        else if token == "font-bold" {
            self.font_bold = true;
        } else if token == "font-mono" {
            self.font_monospace = true;
        }
        // Borders
        else if let Some(val) = token.strip_prefix("border-") {
            // If it's a number, it's width. If it's a color name, it's color.
            if let Ok(width) = val.parse::<f32>() {
                self.border.width = width;
            } else {
                self.border.color = parse_tailwind_color(val);
                if self.border.width == 0.0 {
                    self.border.width = 1.0;
                }
            }
        } else if token == "border" {
            self.border.width = 1.0;
            self.border.color = Color32::from_gray(128);
        }
        // Rounding
        else if token == "rounded" {
            self.rounding = Rounding::same(4.0);
        } else if token == "rounded-md" {
            self.rounding = Rounding::same(6.0);
        } else if token == "rounded-lg" {
            self.rounding = Rounding::same(8.0);
        } else if token == "rounded-xl" {
            self.rounding = Rounding::same(12.0);
        } else if token == "rounded-full" {
            self.rounding = Rounding::same(9999.0);
        }
        // Layout
        else if token == "flex-row" {
            self.layout_mode = LayoutMode::Horizontal;
        } else if token == "flex-col" {
            self.layout_mode = LayoutMode::Vertical;
        }
        // Dimensions
        else if let Some(val) = token.strip_prefix("w-") {
            self.width = Some(parse_arbitrary_size(val));
        } else if let Some(val) = token.strip_prefix("h-") {
            self.height = Some(parse_arbitrary_size(val));
        }
    }

    /// Applies this style to a generic UI Frame (container)
    pub fn to_frame(&self) -> egui::Frame {
        let mut frame = egui::Frame::none();

        if let Some(bg) = self.background_color {
            frame.fill = bg;
        }

        frame.rounding = self.rounding;
        frame.stroke = self.border;
        frame.inner_margin = self.padding;
        frame.outer_margin = self.margin;

        frame
    }
}

// --- Helpers ---

/// Parses "4" -> 16.0 (4 * 4.0 scale), or "[10px]" -> 10.0
fn parse_size(s: &str) -> f32 {
    if s.starts_with('[') && s.ends_with(']') {
        // Arbitrary value: [10px]
        let inner = &s[1..s.len() - 1];
        parse_dimension(inner)
    } else if let Ok(n) = s.parse::<f32>() {
        // Tailwind scale: 1 unit = 4px
        n * 4.0
    } else {
        0.0
    }
}

/// Parses "[100px]" or "full" (not implemented yet)
fn parse_arbitrary_size(s: &str) -> f32 {
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        parse_dimension(inner)
    } else {
        0.0
    }
}

fn parse_dimension(s: &str) -> f32 {
    if let Some(val) = s.strip_suffix("px") {
        val.parse().unwrap_or(0.0)
    } else {
        s.parse().unwrap_or(0.0)
    }
}

fn parse_tailwind_color(s: &str) -> Color32 {
    // Check for arbitrary color: bg-[#ff0000]
    if s.starts_with('[') && s.ends_with(']') {
        let hex = &s[1..s.len() - 1];
        return parse_hex_color(hex);
    }

    // Basic palette (subset)
    match s {
        "white" => Color32::WHITE,
        "black" => Color32::BLACK,
        "transparent" => Color32::TRANSPARENT,

        "red-500" => Color32::from_rgb(239, 68, 68),
        "blue-500" => Color32::from_rgb(59, 130, 246),
        "green-500" => Color32::from_rgb(34, 197, 94),
        "gray-100" => Color32::from_gray(243),
        "gray-200" => Color32::from_gray(229),
        "gray-500" => Color32::from_gray(107),
        "gray-800" => Color32::from_gray(31),
        "gray-900" => Color32::from_gray(17),

        // Fallback
        _ => Color32::from_gray(128), // Debug color to indicate unknown
    }
}

// Helper to parse hex colors
pub fn parse_hex_color(hex: &str) -> Color32 {
    if let Ok(c) = csscolorparser::parse(hex) {
        let [r, g, b, a] = c.to_rgba8();
        Color32::from_rgba_premultiplied(r, g, b, a)
    } else {
        Color32::from_rgb(255, 0, 255) // Error color
    }
}
