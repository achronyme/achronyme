use achronyme_types::value::Value;
use egui::{epaint::Shadow, Align, Color32, Margin, Rounding, Stroke};

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
    // Typography fields
    pub font_size: Option<f32>,
    pub font_bold: bool,
    pub font_italic: bool,
    pub font_monospace: bool,
    pub text_align: Option<Align>,
    // Layout & Spacing
    pub gap: Option<f32>,
    pub main_align: Option<Align>,  // justify-content
    pub cross_align: Option<Align>, // align-items
    // Effects
    pub shadow: Option<Shadow>,
    // Opacity modifiers (0.0 - 1.0)
    pub bg_opacity: Option<f32>,
    pub text_opacity: Option<f32>,
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
        } else if let Some(val) = token.strip_prefix("mx-") {
            let s = parse_size(val);
            self.margin.left = s;
            self.margin.right = s;
        } else if let Some(val) = token.strip_prefix("my-") {
            let s = parse_size(val);
            self.margin.top = s;
            self.margin.bottom = s;
        } else if let Some(val) = token.strip_prefix("mt-") {
            self.margin.top = parse_size(val);
        } else if let Some(val) = token.strip_prefix("mb-") {
            self.margin.bottom = parse_size(val);
        } else if let Some(val) = token.strip_prefix("ml-") {
            self.margin.left = parse_size(val);
        } else if let Some(val) = token.strip_prefix("mr-") {
            self.margin.right = parse_size(val);
        }
        // Gap (Spacing)
        else if let Some(val) = token.strip_prefix("gap-") {
            self.gap = Some(parse_size(val));
        }
        // Layout Direction
        else if token == "flex-row" {
            self.layout_mode = LayoutMode::Horizontal;
        } else if token == "flex-col" {
            self.layout_mode = LayoutMode::Vertical;
        }
        // Alignment (Items -> Cross Axis)
        else if let Some(val) = token.strip_prefix("items-") {
            match val {
                "start" => self.cross_align = Some(Align::Min),
                "center" => self.cross_align = Some(Align::Center),
                "end" => self.cross_align = Some(Align::Max),
                _ => {}
            }
        }
        // Justification (Justify -> Main Axis)
        else if let Some(val) = token.strip_prefix("justify-") {
            match val {
                "start" => self.main_align = Some(Align::Min),
                "center" => self.main_align = Some(Align::Center),
                "end" => self.main_align = Some(Align::Max),
                // TODO: Implement proper space-between/around logic.
                // For now, map to Start to avoid parsing issues.
                "between" | "around" => self.main_align = Some(Align::Min),
                _ => {}
            }
        }
        // Colors (Background)
        else if let Some(val) = token.strip_prefix("bg-") {
            self.background_color = Some(parse_tailwind_color(val));
        }
        // Colors (Text)
        else if let Some(val) = token.strip_prefix("text-") {
            // Check if it's a size, alignment, or color
            match val {
                // Sizes
                "xs" => self.font_size = Some(10.0),
                "sm" => self.font_size = Some(12.0),
                "base" => self.font_size = Some(14.0),
                "lg" => self.font_size = Some(18.0),
                "xl" => self.font_size = Some(20.0),
                "2xl" => self.font_size = Some(24.0),
                "3xl" => self.font_size = Some(30.0),
                "4xl" => self.font_size = Some(36.0),
                "5xl" => self.font_size = Some(48.0),
                "6xl" => self.font_size = Some(60.0),
                // Alignment
                "left" => self.text_align = Some(Align::Min),
                "center" => self.text_align = Some(Align::Center),
                "right" => self.text_align = Some(Align::Max),
                // Color
                _ => self.text_color = Some(parse_tailwind_color(val)),
            }
        }
        // Font Weight / Style
        else if token == "font-bold" {
            self.font_bold = true;
        } else if token == "font-mono" {
            self.font_monospace = true;
        } else if token == "italic" {
            self.font_italic = true;
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
        else if token == "rounded-none" {
            self.rounding = Rounding::ZERO;
        } else if token == "rounded-sm" {
            self.rounding = Rounding::same(2.0);
        } else if token == "rounded" {
            self.rounding = Rounding::same(4.0);
        } else if token == "rounded-md" {
            self.rounding = Rounding::same(6.0);
        } else if token == "rounded-lg" {
            self.rounding = Rounding::same(8.0);
        } else if token == "rounded-xl" {
            self.rounding = Rounding::same(12.0);
        } else if token == "rounded-2xl" {
            self.rounding = Rounding::same(16.0);
        } else if token == "rounded-3xl" {
            self.rounding = Rounding::same(24.0);
        } else if token == "rounded-full" {
            self.rounding = Rounding::same(9999.0);
        }
        // Dimensions
        else if let Some(val) = token.strip_prefix("w-") {
            if val == "full" {
                self.width = Some(f32::INFINITY);
            } else {
                self.width = Some(parse_arbitrary_size(val));
            }
        } else if let Some(val) = token.strip_prefix("h-") {
            if val == "full" {
                self.height = Some(f32::INFINITY);
            } else {
                self.height = Some(parse_arbitrary_size(val));
            }
        }
        // Shadows
        else if token == "shadow-none" {
            self.shadow = Some(Shadow::NONE);
        } else if token == "shadow-sm" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 1.0),
                blur: 2.0,
                spread: 0.0,
                color: Color32::from_black_alpha(40),
            });
        } else if token == "shadow" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 1.0),
                blur: 3.0,
                spread: 0.0,
                color: Color32::from_black_alpha(50),
            });
        } else if token == "shadow-md" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 4.0),
                blur: 6.0,
                spread: -1.0,
                color: Color32::from_black_alpha(50),
            });
        } else if token == "shadow-lg" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 10.0),
                blur: 15.0,
                spread: -3.0,
                color: Color32::from_black_alpha(50),
            });
        } else if token == "shadow-xl" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 20.0),
                blur: 25.0,
                spread: -5.0,
                color: Color32::from_black_alpha(50),
            });
        } else if token == "shadow-2xl" {
            self.shadow = Some(Shadow {
                offset: egui::vec2(0.0, 25.0),
                blur: 50.0,
                spread: -12.0,
                color: Color32::from_black_alpha(60),
            });
        }
        // Opacity
        else if let Some(val) = token.strip_prefix("bg-opacity-") {
            if let Ok(n) = val.parse::<u8>() {
                self.bg_opacity = Some(n as f32 / 100.0);
            }
        } else if let Some(val) = token.strip_prefix("text-opacity-") {
            if let Ok(n) = val.parse::<u8>() {
                self.text_opacity = Some(n as f32 / 100.0);
            }
        }
    }

    /// Applies this style to a generic UI Frame (container)
    pub fn to_frame(&self) -> egui::Frame {
        let mut frame = egui::Frame::none();

        if let Some(bg) = self.background_color {
            // Apply opacity if set
            if let Some(opacity) = self.bg_opacity {
                let alpha = (opacity * 255.0) as u8;
                frame.fill = Color32::from_rgba_unmultiplied(bg.r(), bg.g(), bg.b(), alpha);
            } else {
                frame.fill = bg;
            }
        }

        frame.rounding = self.rounding;
        frame.stroke = self.border;
        frame.inner_margin = self.padding;
        frame.outer_margin = self.margin;

        if let Some(shadow) = self.shadow {
            frame.shadow = shadow;
        }

        frame
    }

    /// Returns the text color with opacity applied if set
    pub fn effective_text_color(&self) -> Option<Color32> {
        match (self.text_color, self.text_opacity) {
            (Some(color), Some(opacity)) => {
                let alpha = (opacity * 255.0) as u8;
                Some(Color32::from_rgba_unmultiplied(
                    color.r(),
                    color.g(),
                    color.b(),
                    alpha,
                ))
            }
            (Some(color), None) => Some(color),
            _ => None,
        }
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

        // Grays
        "gray-100" => Color32::from_gray(243),
        "gray-200" => Color32::from_gray(229),
        "gray-300" => Color32::from_gray(209),
        "gray-400" => Color32::from_gray(156),
        "gray-500" => Color32::from_gray(107),
        "gray-600" => Color32::from_gray(75),
        "gray-700" => Color32::from_gray(55),
        "gray-800" => Color32::from_gray(31),
        "gray-900" => Color32::from_gray(17),

        // Reds
        "red-400" => Color32::from_rgb(248, 113, 113),
        "red-500" => Color32::from_rgb(239, 68, 68),
        "red-600" => Color32::from_rgb(220, 38, 38),

        // Blues
        "blue-400" => Color32::from_rgb(96, 165, 250),
        "blue-500" => Color32::from_rgb(59, 130, 246),
        "blue-600" => Color32::from_rgb(37, 99, 235),

        // Greens
        "green-400" => Color32::from_rgb(74, 222, 128),
        "green-500" => Color32::from_rgb(34, 197, 94),
        "green-600" => Color32::from_rgb(22, 163, 74),

        // Yellows
        "yellow-400" => Color32::from_rgb(250, 204, 21),
        "yellow-500" => Color32::from_rgb(234, 179, 8),
        "yellow-600" => Color32::from_rgb(202, 138, 4),

        // Purples
        "purple-400" => Color32::from_rgb(192, 132, 252),
        "purple-500" => Color32::from_rgb(168, 85, 247),
        "purple-600" => Color32::from_rgb(147, 51, 234),

        // Cyans
        "cyan-400" => Color32::from_rgb(34, 211, 238),
        "cyan-500" => Color32::from_rgb(6, 182, 212),
        "cyan-600" => Color32::from_rgb(8, 145, 178),

        // Magentas / Pinks
        "pink-400" => Color32::from_rgb(244, 114, 182),
        "pink-500" => Color32::from_rgb(236, 72, 153),
        "pink-600" => Color32::from_rgb(219, 39, 119),

        // Oranges
        "orange-400" => Color32::from_rgb(251, 146, 60),
        "orange-500" => Color32::from_rgb(249, 115, 22),
        "orange-600" => Color32::from_rgb(234, 88, 12),

        // Teals
        "teal-400" => Color32::from_rgb(45, 212, 191),
        "teal-500" => Color32::from_rgb(20, 184, 166),
        "teal-600" => Color32::from_rgb(13, 148, 136),

        // Indigos
        "indigo-400" => Color32::from_rgb(129, 140, 248),
        "indigo-500" => Color32::from_rgb(99, 102, 241),
        "indigo-600" => Color32::from_rgb(79, 70, 229),

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
