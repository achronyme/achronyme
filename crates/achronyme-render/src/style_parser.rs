//! Style Parser - Converts Tailwind-like utility strings to style configurations
//!
//! Uses Pest grammar for robust parsing with clear error messages.

use crate::layout::LayoutStyle;
use crate::node::NodeStyle;
use pest::Parser;
use pest_derive::Parser;
use taffy::prelude::*;

#[derive(Parser)]
#[grammar = "style.pest"]
pub struct StyleParser;

/// Combined style output from parsing
#[derive(Debug, Clone, Default)]
pub struct ParsedStyle {
    /// Layout properties (for Taffy)
    pub layout: LayoutStyle,
    /// Visual properties (for rendering)
    pub visual: NodeStyle,
}

/// Parse a style string into layout and visual styles
pub fn parse_style(input: &str) -> Result<ParsedStyle, String> {
    let pairs = StyleParser::parse(Rule::style_string, input)
        .map_err(|e| format!("Style parse error: {}", e))?;

    let mut style = ParsedStyle::default();

    for pair in pairs {
        if pair.as_rule() == Rule::style_string {
            for inner in pair.into_inner() {
                process_utility(&mut style, inner);
            }
        }
    }

    Ok(style)
}

fn process_utility(style: &mut ParsedStyle, pair: pest::iterators::Pair<Rule>) {
    match pair.as_rule() {
        Rule::flex_direction => {
            let text = pair.as_str();
            style.layout.direction = if text == "flex-row" {
                FlexDirection::Row
            } else {
                FlexDirection::Column
            };
        }

        Rule::justify_content => {
            let value = pair.into_inner().next().unwrap().as_str();
            style.layout.justify_content = Some(match value {
                "start" => JustifyContent::Start,
                "center" => JustifyContent::Center,
                "end" => JustifyContent::End,
                "between" => JustifyContent::SpaceBetween,
                "around" => JustifyContent::SpaceAround,
                "evenly" => JustifyContent::SpaceEvenly,
                _ => JustifyContent::Start,
            });
        }

        Rule::align_items => {
            let value = pair.into_inner().next().unwrap().as_str();
            style.layout.align_items = Some(match value {
                "start" => AlignItems::Start,
                "center" => AlignItems::Center,
                "end" => AlignItems::End,
                "stretch" => AlignItems::Stretch,
                "baseline" => AlignItems::Baseline,
                _ => AlignItems::Start,
            });
        }

        Rule::gap => {
            if let Some(value) = extract_spacing_value(pair) {
                style.layout.gap = value;
            }
        }

        Rule::padding => {
            let mut inner = pair.into_inner();
            let prefix = inner.next().unwrap().as_str();
            let value = if let Some(next) = inner.next() {
                parse_spacing_token(next)
            } else {
                0.0
            };

            match prefix {
                "p" => style.layout.padding = value,
                "px" => {
                    style.layout.padding_left = Some(value);
                    style.layout.padding_right = Some(value);
                }
                "py" => {
                    style.layout.padding_top = Some(value);
                    style.layout.padding_bottom = Some(value);
                }
                "pt" => style.layout.padding_top = Some(value),
                "pb" => style.layout.padding_bottom = Some(value),
                "pl" => style.layout.padding_left = Some(value),
                "pr" => style.layout.padding_right = Some(value),
                _ => {}
            }
        }

        Rule::margin => {
            let mut inner = pair.into_inner();
            let prefix = inner.next().unwrap().as_str();
            let value = if let Some(next) = inner.next() {
                parse_spacing_token(next)
            } else {
                0.0
            };

            match prefix {
                "m" => style.layout.margin = value,
                "mx" => {
                    style.layout.margin_left = Some(value);
                    style.layout.margin_right = Some(value);
                }
                "my" => {
                    style.layout.margin_top = Some(value);
                    style.layout.margin_bottom = Some(value);
                }
                "mt" => style.layout.margin_top = Some(value),
                "mb" => style.layout.margin_bottom = Some(value),
                "ml" => style.layout.margin_left = Some(value),
                "mr" => style.layout.margin_right = Some(value),
                _ => {}
            }
        }

        Rule::width => {
            if let Some(inner) = pair.into_inner().next() {
                style.layout.width = parse_size_value(inner);
            }
        }

        Rule::height => {
            if let Some(inner) = pair.into_inner().next() {
                style.layout.height = parse_size_value(inner);
            }
        }

        Rule::background => {
            if let Some(color) = extract_color(pair) {
                style.visual.background_color = Some(color);
            }
        }

        Rule::background_opacity => {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::opacity_num {
                    let opacity = inner.as_str().parse::<f32>().unwrap_or(100.0) / 100.0;
                    style.visual.background_opacity = Some(opacity);
                }
            }
        }

        Rule::text_style => {
            for inner in pair.into_inner() {
                match inner.as_rule() {
                    Rule::text_size => {
                        style.visual.font_size = match inner.as_str() {
                            "xs" => 10.0,
                            "sm" => 12.0,
                            "base" => 14.0,
                            "lg" => 18.0,
                            "xl" => 20.0,
                            "2xl" => 24.0,
                            "3xl" => 30.0,
                            "4xl" => 36.0,
                            "5xl" => 48.0,
                            "6xl" => 60.0,
                            _ => 14.0,
                        };
                    }
                    Rule::text_align => {
                        style.visual.text_align = Some(inner.as_str().to_string());
                    }
                    Rule::color_value => {
                        if let Some(color) = parse_color_value(inner) {
                            style.visual.text_color = Some(color);
                        }
                    }
                    _ => {
                        // It's a color (fallback)
                        if let Some(color) = parse_color_from_pair(inner) {
                            style.visual.text_color = Some(color);
                        }
                    }
                }
            }
        }

        Rule::text_opacity => {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::opacity_num {
                    let opacity = inner.as_str().parse::<f32>().unwrap_or(100.0) / 100.0;
                    style.visual.text_opacity = Some(opacity);
                }
            }
        }

        Rule::font_weight => {
            if let Some(inner) = pair.into_inner().next() {
                style.visual.font_bold = matches!(
                    inner.as_str(),
                    "semibold" | "bold" | "extrabold" | "black"
                );
            }
        }

        Rule::font_family => {
            if let Some(inner) = pair.into_inner().next() {
                style.visual.font_monospace = inner.as_str() == "mono";
            }
        }

        Rule::font_style => {
            style.visual.font_italic = pair.as_str() == "italic";
        }

        Rule::border => {
            let mut width = 1.0;
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::border_width || inner.as_rule() == Rule::scale_number {
                    width = inner.as_str().parse().unwrap_or(1.0);
                }
            }
            style.visual.border_width = width;
        }

        Rule::border_color => {
            if let Some(color) = extract_color(pair) {
                style.visual.border_color = Some(color);
            }
        }

        Rule::rounded => {
            let mut radius = 4.0; // default "rounded"
            for inner in pair.into_inner() {
                match inner.as_rule() {
                    Rule::rounded_size => {
                        radius = match inner.as_str() {
                            "none" => 0.0,
                            "sm" => 2.0,
                            "md" => 6.0,
                            "lg" => 8.0,
                            "xl" => 12.0,
                            "2xl" => 16.0,
                            "3xl" => 24.0,
                            "full" => 9999.0,
                            _ => 4.0,
                        };
                    }
                    Rule::arbitrary_length => {
                        radius = parse_arbitrary_length(inner);
                    }
                    _ => {}
                }
            }
            style.visual.border_radius = radius;
        }

        Rule::shadow => {
            // Shadow sizes map to blur/spread values
            // For now just store a shadow level
            let level = pair
                .into_inner()
                .next()
                .map(|p| match p.as_str() {
                    "none" => 0,
                    "sm" => 1,
                    "md" => 2,
                    "lg" => 3,
                    "xl" => 4,
                    "2xl" => 5,
                    _ => 2,
                })
                .unwrap_or(2);
            style.visual.shadow_level = level;
        }

        Rule::opacity => {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::opacity_num {
                    let opacity = inner.as_str().parse::<f32>().unwrap_or(100.0) / 100.0;
                    style.visual.opacity = Some(opacity);
                }
            }
        }

        _ => {} // Ignore EOI and other non-utility rules
    }
}

fn extract_spacing_value(pair: pest::iterators::Pair<Rule>) -> Option<f32> {
    for inner in pair.into_inner() {
        return Some(parse_spacing_token(inner));
    }
    None
}

fn parse_spacing_token(pair: pest::iterators::Pair<Rule>) -> f32 {
    match pair.as_rule() {
        Rule::scale_number => {
            let n: f32 = pair.as_str().parse().unwrap_or(0.0);
            n * 4.0 // Tailwind scale: 1 = 4px
        }
        Rule::arbitrary_length => parse_arbitrary_length(pair),
        _ => 0.0,
    }
}

fn parse_arbitrary_length(pair: pest::iterators::Pair<Rule>) -> f32 {
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::length_inner {
            let text = inner.as_str();
            // Remove unit suffix and # prefix if present
            let text = text.trim_start_matches('#');
            let numeric: String = text.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
            return numeric.parse().unwrap_or(0.0);
        }
    }
    0.0
}

fn parse_size_value(pair: pest::iterators::Pair<Rule>) -> Option<f32> {
    match pair.as_rule() {
        Rule::size_keyword => match pair.as_str() {
            "full" => Some(f32::INFINITY), // Signals "100%"
            "auto" => None,
            "screen" => Some(f32::INFINITY),
            _ => None,
        },
        Rule::scale_number => {
            let n: f32 = pair.as_str().parse().unwrap_or(0.0);
            Some(n * 4.0)
        }
        Rule::arbitrary_length => Some(parse_arbitrary_length(pair)),
        _ => None,
    }
}

fn extract_color(pair: pest::iterators::Pair<Rule>) -> Option<u32> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::color_value => {
                return parse_color_value(inner);
            }
            _ => {
                if let Some(color) = parse_color_from_pair(inner) {
                    return Some(color);
                }
            }
        }
    }
    None
}

fn parse_color_value(pair: pest::iterators::Pair<Rule>) -> Option<u32> {
    for inner in pair.into_inner() {
        if let Some(color) = parse_color_from_pair(inner) {
            return Some(color);
        }
    }
    None
}

fn parse_color_from_pair(pair: pest::iterators::Pair<Rule>) -> Option<u32> {
    match pair.as_rule() {
        Rule::hex_color => {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::hex_digits {
                    return parse_hex_color(inner.as_str());
                }
            }
            None
        }
        Rule::named_color => {
            // named_color is atomic (@), so we parse the string directly
            // Format: "colorname-shade" e.g. "blue-500"
            let text = pair.as_str();
            if let Some(dash_pos) = text.rfind('-') {
                let color_name = &text[..dash_pos];
                let shade = &text[dash_pos + 1..];
                Some(get_named_color(color_name, shade))
            } else {
                Some(get_named_color(text, "500"))
            }
        }
        Rule::keyword_color => Some(match pair.as_str() {
            "white" => 0xFFFFFFFF,
            "black" => 0xFF000000,
            "transparent" => 0x00000000,
            "current" => 0xFFFFFFFF, // fallback
            _ => 0xFFFFFFFF,
        }),
        _ => None,
    }
}

fn parse_hex_color(hex: &str) -> Option<u32> {
    let len = hex.len();
    match len {
        3 => {
            // RGB -> RRGGBB
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            Some(0xFF000000 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
        }
        4 => {
            // RGBA -> RRGGBBAA
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            let a = u8::from_str_radix(&hex[3..4], 16).ok()? * 17;
            Some((a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
        }
        6 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            Some(0xFF000000 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
        }
        8 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
            Some((a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
        }
        _ => None,
    }
}

/// Get a named color from Tailwind palette
fn get_named_color(name: &str, shade: &str) -> u32 {
    // Subset of Tailwind colors
    match (name, shade) {
        // Gray
        ("gray", "50") => 0xFFF9FAFB,
        ("gray", "100") => 0xFFF3F4F6,
        ("gray", "200") => 0xFFE5E7EB,
        ("gray", "300") => 0xFFD1D5DB,
        ("gray", "400") => 0xFF9CA3AF,
        ("gray", "500") => 0xFF6B7280,
        ("gray", "600") => 0xFF4B5563,
        ("gray", "700") => 0xFF374151,
        ("gray", "800") => 0xFF1F2937,
        ("gray", "900") => 0xFF111827,

        // Red
        ("red", "400") => 0xFFF87171,
        ("red", "500") => 0xFFEF4444,
        ("red", "600") => 0xFFDC2626,

        // Green
        ("green", "400") => 0xFF4ADE80,
        ("green", "500") => 0xFF22C55E,
        ("green", "600") => 0xFF16A34A,

        // Blue
        ("blue", "400") => 0xFF60A5FA,
        ("blue", "500") => 0xFF3B82F6,
        ("blue", "600") => 0xFF2563EB,

        // Yellow
        ("yellow", "400") => 0xFFFACC15,
        ("yellow", "500") => 0xFFEAB308,
        ("yellow", "600") => 0xFFCA8A04,

        // Purple
        ("purple", "400") => 0xFFC084FC,
        ("purple", "500") => 0xFFA855F7,
        ("purple", "600") => 0xFF9333EA,

        // Pink
        ("pink", "400") => 0xFFF472B6,
        ("pink", "500") => 0xFFEC4899,
        ("pink", "600") => 0xFFDB2777,

        // Orange
        ("orange", "400") => 0xFFFB923C,
        ("orange", "500") => 0xFFF97316,
        ("orange", "600") => 0xFFEA580C,

        // Cyan
        ("cyan", "400") => 0xFF22D3EE,
        ("cyan", "500") => 0xFF06B6D4,
        ("cyan", "600") => 0xFF0891B2,

        // Teal
        ("teal", "400") => 0xFF2DD4BF,
        ("teal", "500") => 0xFF14B8A6,
        ("teal", "600") => 0xFF0D9488,

        // Indigo
        ("indigo", "400") => 0xFF818CF8,
        ("indigo", "500") => 0xFF6366F1,
        ("indigo", "600") => 0xFF4F46E5,

        // Emerald
        ("emerald", "400") => 0xFF34D399,
        ("emerald", "500") => 0xFF10B981,
        ("emerald", "600") => 0xFF059669,

        // Default fallback
        _ => 0xFF888888,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parsing() {
        let result = parse_style("flex-col items-center gap-4").unwrap();
        assert_eq!(result.layout.direction, FlexDirection::Column);
        assert_eq!(result.layout.align_items, Some(AlignItems::Center));
        assert_eq!(result.layout.gap, 16.0); // 4 * 4 = 16
    }

    #[test]
    fn test_colors() {
        let result = parse_style("bg-blue-500 text-white").unwrap();
        assert_eq!(result.visual.background_color, Some(0xFF3B82F6));
        assert_eq!(result.visual.text_color, Some(0xFFFFFFFF));
    }

    #[test]
    fn test_hex_colors() {
        let result = parse_style("bg-[#1a1a1a]").unwrap();
        assert_eq!(result.visual.background_color, Some(0xFF1A1A1A));
    }

    #[test]
    fn test_arbitrary_values() {
        let result = parse_style("w-[300px] h-[200px] p-[24px]").unwrap();
        assert_eq!(result.layout.width, Some(300.0));
        assert_eq!(result.layout.height, Some(200.0));
        assert_eq!(result.layout.padding, 24.0);
    }

    #[test]
    fn test_typography() {
        let result = parse_style("text-2xl font-bold italic").unwrap();
        assert_eq!(result.visual.font_size, 24.0);
        assert!(result.visual.font_bold);
        assert!(result.visual.font_italic);
    }

    #[test]
    fn test_rounded() {
        let result = parse_style("rounded-lg").unwrap();
        assert_eq!(result.visual.border_radius, 8.0);

        let result2 = parse_style("rounded-full").unwrap();
        assert_eq!(result2.visual.border_radius, 9999.0);
    }

    #[test]
    fn test_complex_style() {
        let result = parse_style(
            "flex-col items-center justify-center gap-4 p-6 bg-[#333333] rounded-xl shadow-lg"
        ).unwrap();

        assert_eq!(result.layout.direction, FlexDirection::Column);
        assert_eq!(result.layout.align_items, Some(AlignItems::Center));
        assert_eq!(result.layout.justify_content, Some(JustifyContent::Center));
        assert_eq!(result.layout.gap, 16.0);
        assert_eq!(result.layout.padding, 24.0);
        assert_eq!(result.visual.background_color, Some(0xFF333333));
        assert_eq!(result.visual.border_radius, 12.0);
        assert_eq!(result.visual.shadow_level, 3);
    }

    #[test]
    fn test_full_width() {
        let result = parse_style("w-full h-full").unwrap();
        assert_eq!(result.layout.width, Some(f32::INFINITY));
        assert_eq!(result.layout.height, Some(f32::INFINITY));
    }

    #[test]
    fn test_flex_row_parsing() {
        // Test exact string from test-layout.soc
        let result = parse_style("bg-[#333333] p-4 rounded-lg flex-row gap-2 items-center").unwrap();
        assert_eq!(result.layout.direction, FlexDirection::Row, "flex-row should set direction to Row");
        assert_eq!(result.layout.gap, 8.0, "gap-2 should be 8px"); // 2 * 4 = 8
        assert_eq!(result.layout.align_items, Some(AlignItems::Center));
        assert_eq!(result.layout.padding, 16.0, "p-4 should be 16px"); // 4 * 4 = 16
    }

    #[test]
    fn test_flex_row_simple() {
        let result = parse_style("flex-row gap-2").unwrap();
        assert_eq!(result.layout.direction, FlexDirection::Row, "flex-row should set direction to Row");
        assert_eq!(result.layout.gap, 8.0, "gap-2 should be 8px");
    }
}
