//! Layout Strategy Layer
//!
//! This module bridges the gap between CSS/Tailwind mental model and egui's
//! immediate mode rendering. It resolves user intent into concrete egui plans.

use crate::style::{LayoutMode, StyleConfig};
use egui::{Align, Align2, Layout, Vec2};

/// Information about the parent container that affects layout decisions.
/// This context is gathered at render time from the current egui::Ui state.
#[derive(Clone, Debug)]
pub struct LayoutContext {
    /// Available width from parent (None = unconstrained/infinite)
    pub available_width: Option<f32>,
    /// Available height from parent (None = unconstrained/infinite)
    pub available_height: Option<f32>,
    /// Whether this container is the root (CentralPanel)
    pub is_root: bool,
}

impl LayoutContext {
    /// Creates a LayoutContext by inspecting the current UI state
    pub fn from_ui(ui: &egui::Ui, is_root: bool) -> Self {
        let available = ui.available_size();
        Self {
            available_width: if available.x.is_finite() && available.x > 0.0 {
                Some(available.x)
            } else {
                None
            },
            available_height: if available.y.is_finite() && available.y > 0.0 {
                Some(available.y)
            } else {
                None
            },
            is_root,
        }
    }

    /// Returns true if the cross-axis is unbounded (could cause "explosion")
    pub fn cross_axis_is_unbounded(&self, direction: &LayoutMode) -> bool {
        match direction {
            LayoutMode::Horizontal => self.available_height.is_none(),
            LayoutMode::Vertical => self.available_width.is_none(),
        }
    }

    /// Returns true if the main-axis is unbounded
    pub fn main_axis_is_unbounded(&self, direction: &LayoutMode) -> bool {
        match direction {
            LayoutMode::Horizontal => self.available_width.is_none(),
            LayoutMode::Vertical => self.available_height.is_none(),
        }
    }
}

/// Strategy for how to size the container before applying layout
#[derive(Clone, Debug, Default)]
pub enum SizingStrategy {
    /// Use available space (default egui behavior)
    #[default]
    UseAvailable,

    /// Shrink-wrap to content size, then apply alignment within parent space.
    /// This prevents the "explosion" problem where centering in infinite space
    /// causes the container to consume all available space.
    ShrinkWrap {
        /// How to align the shrink-wrapped content within available space
        content_align: Option<Align2>,
    },

    /// Use explicit dimensions provided by the user
    Fixed {
        width: Option<f32>,
        height: Option<f32>,
    },
}

/// The concrete instructions for egui, produced after strategy resolution.
/// This is what components.rs will execute - no decision-making needed.
#[derive(Clone, Debug)]
pub struct EguiLayoutPlan {
    /// The base layout direction and alignment
    pub layout: Layout,
    /// How to handle container sizing
    pub sizing_strategy: SizingStrategy,
    /// Spacing between items (gap)
    pub item_spacing: Option<Vec2>,
}

impl Default for EguiLayoutPlan {
    fn default() -> Self {
        Self {
            layout: Layout::top_down(Align::Min),
            sizing_strategy: SizingStrategy::UseAvailable,
            item_spacing: None,
        }
    }
}

impl StyleConfig {
    /// Resolves the user's styling intent into a concrete egui execution plan.
    ///
    /// This is the core of the Layout Strategy Layer. It takes into account:
    /// - What the user asked for (self)
    /// - What space is available (ctx)
    /// - What egui can actually do safely
    ///
    /// KEY INSIGHT: In CSS/Tailwind, containers shrink-wrap by default.
    /// In egui, containers expand to fill available space by default.
    /// We invert egui's default: ShrinkWrap unless explicitly asked to expand.
    pub fn resolve_layout(&self, _ctx: &LayoutContext) -> EguiLayoutPlan {
        let mut plan = EguiLayoutPlan::default();

        // 1. Base layout direction
        plan.layout = match self.layout_mode {
            LayoutMode::Horizontal => Layout::left_to_right(Align::Min),
            LayoutMode::Vertical => Layout::top_down(Align::Min),
        };

        // 2. Apply alignments to the layout
        if let Some(align) = self.main_align {
            plan.layout = plan.layout.with_main_align(align);
        }
        if let Some(align) = self.cross_align {
            plan.layout = plan.layout.with_cross_align(align);
        }

        // 3. Determine sizing strategy
        // CSS/Tailwind mental model: containers shrink-wrap by default
        // Only expand when user explicitly asks for it (w-full, h-full, w-[X], h-[X])
        let has_explicit_width = self.width.is_some();
        let has_explicit_height = self.height.is_some();

        if has_explicit_width || has_explicit_height {
            // User specified dimensions - use Fixed strategy
            plan.sizing_strategy = SizingStrategy::Fixed {
                width: self.width,
                height: self.height,
            };
        } else {
            // DEFAULT: Shrink-wrap to content (CSS/Tailwind behavior)
            plan.sizing_strategy = SizingStrategy::ShrinkWrap {
                content_align: self.compute_shrink_wrap_align(),
            };
        }

        // 4. Gap/spacing
        if let Some(gap) = self.gap {
            plan.item_spacing = Some(Vec2::splat(gap));
        }

        plan
    }

    /// Compute alignment for shrink-wrapped content
    fn compute_shrink_wrap_align(&self) -> Option<Align2> {
        // For now, just return a reasonable default based on alignments
        match (self.main_align, self.cross_align) {
            (Some(Align::Center), Some(Align::Center)) => Some(Align2::CENTER_CENTER),
            (Some(Align::Center), _) => Some(Align2::CENTER_TOP),
            (_, Some(Align::Center)) => Some(Align2::LEFT_CENTER),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_shrink_wrap() {
        let config = StyleConfig::default();

        let ctx = LayoutContext {
            available_width: Some(800.0),
            available_height: Some(600.0),
            is_root: false,
        };

        let plan = config.resolve_layout(&ctx);

        // Default should be shrink-wrap (CSS/Tailwind behavior)
        assert!(matches!(
            plan.sizing_strategy,
            SizingStrategy::ShrinkWrap { .. }
        ));
    }

    #[test]
    fn test_explicit_dimensions_use_fixed() {
        let mut config = StyleConfig::default();
        config.width = Some(100.0);
        config.height = Some(50.0);

        let ctx = LayoutContext {
            available_width: Some(800.0),
            available_height: Some(600.0),
            is_root: false,
        };

        let plan = config.resolve_layout(&ctx);

        // Explicit dimensions should use Fixed strategy
        assert!(matches!(
            plan.sizing_strategy,
            SizingStrategy::Fixed {
                width: Some(100.0),
                height: Some(50.0)
            }
        ));
    }

    #[test]
    fn test_w_full_uses_fixed_with_infinity() {
        let mut config = StyleConfig::default();
        config.width = Some(f32::INFINITY); // w-full

        let ctx = LayoutContext {
            available_width: Some(800.0),
            available_height: Some(600.0),
            is_root: false,
        };

        let plan = config.resolve_layout(&ctx);

        // w-full should trigger Fixed with infinite width
        assert!(matches!(
            plan.sizing_strategy,
            SizingStrategy::Fixed { width: Some(w), .. } if w.is_infinite()
        ));
    }

    #[test]
    fn test_alignments_are_applied() {
        let mut config = StyleConfig::default();
        config.cross_align = Some(Align::Center);

        let ctx = LayoutContext {
            available_width: Some(800.0),
            available_height: Some(600.0),
            is_root: false,
        };

        let plan = config.resolve_layout(&ctx);

        // Cross-align should be applied to layout
        assert_eq!(plan.layout.cross_align(), Align::Center);
    }
}
