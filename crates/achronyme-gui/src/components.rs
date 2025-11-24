use crate::bridge;
use crate::style::{LayoutMode, StyleConfig};
use achronyme_types::value::Value;
use egui::{FontFamily, RichText};
use egui_plot::{Legend, Line, Plot, PlotPoints, Points};

/// Renders a styled label: ui.label("Hello", "text-red-500 font-bold")
pub fn label(text: &str, style: &Value) {
    if let Some(ui) = bridge::get_ui() {
        let config = StyleConfig::from_value(style);

        let mut rich_text = RichText::new(text);

        if let Some(color) = config.text_color {
            rich_text = rich_text.color(color);
        }

        if let Some(size) = config.font_size {
            rich_text = rich_text.size(size);
        }

        if config.font_bold {
            rich_text = rich_text.strong();
        }

        if config.font_monospace {
            rich_text = rich_text.family(FontFamily::Monospace);
        }

        ui.label(rich_text);
    }
}

/// Renders a styled button: ui.button("Click Me", "bg-blue-500 rounded")
/// Returns true if clicked.
pub fn button(text: &str, style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        let config = StyleConfig::from_value(style);

        // Apply text styles to the button label
        let mut rich_text = RichText::new(text);
        if let Some(color) = config.text_color {
            rich_text = rich_text.color(color); // This sets the TEXT color
        }
        if let Some(size) = config.font_size {
            rich_text = rich_text.size(size);
        }
        if config.font_bold {
            rich_text = rich_text.strong();
        }

        let mut btn = egui::Button::new(rich_text);

        if let Some(bg) = config.background_color {
            btn = btn.fill(bg);
        }

        ui.add(btn).clicked()
    } else {
        false
    }
}

/// Renders a container (Box/Div): ui.box({ style: "...", children: () => { ... } })
pub fn container<F>(style: &Value, children: F)
where
    F: FnOnce(),
{
    if let Some(ui) = bridge::get_ui() {
        let config = StyleConfig::from_value(style);
        let frame = config.to_frame();

        frame.show(ui, |ui| {
            // Apply explicit dimensions if provided
            if let Some(w) = config.width {
                ui.set_min_width(w);
                ui.set_max_width(w);
            }
            if let Some(h) = config.height {
                ui.set_min_height(h);
                ui.set_max_height(h);
            }

            // Apply layout direction
            match config.layout_mode {
                LayoutMode::Horizontal => {
                    ui.horizontal(|ui| {
                        bridge::with_ui_context(ui, children);
                    });
                }
                LayoutMode::Vertical => {
                    ui.vertical(|ui| {
                        bridge::with_ui_context(ui, children);
                    });
                }
            }
        });
    }
}

/// Renders a tab bar. Returns the new index if changed, otherwise None.
pub fn tabs(titles: &[String], current_index: usize, _style: &Value) -> Option<usize> {
    if let Some(ui) = bridge::get_ui() {
        let mut new_index = None;
        ui.horizontal(|ui| {
            for (i, title) in titles.iter().enumerate() {
                if ui.selectable_label(current_index == i, title).clicked() {
                    new_index = Some(i);
                }
            }
        });
        return new_index;
    }
    None
}

/// Renders a text input. Returns true if changed.
pub fn text_input(text: &mut String, style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        let _config = StyleConfig::from_value(style);
        // TODO: Apply styles to text input (frame, text color, etc)
        // For now standard
        let response = ui.text_edit_singleline(text);
        return response.changed();
    }
    false
}

/// Renders a slider. Returns true if changed.
pub fn slider(value: &mut f64, min: f64, max: f64, style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        let _config = StyleConfig::from_value(style);
        let response = ui.add(egui::Slider::new(value, min..=max));
        return response.changed();
    }
    false
}

/// Renders a checkbox. Returns true if changed.
pub fn checkbox(checked: &mut bool, text: &str, _style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        // TODO: Style support
        let response = ui.checkbox(checked, text);
        return response.changed();
    }
    false
}

/// Renders a radio button. Returns true if clicked (selected).
pub fn radio(selected: bool, text: &str, _style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        // TODO: Style support
        let response = ui.radio(selected, text);
        return response.clicked();
    }
    false
}

/// Renders a combobox. Returns true if changed.
pub fn combobox(current_value: &mut String, options: &[String], _style: &Value) -> bool {
    if let Some(ui) = bridge::get_ui() {
        // TODO: Style support
        let mut changed = false;
        egui::ComboBox::from_id_salt(ui.next_auto_id())
            .selected_text(current_value.clone())
            .show_ui(ui, |ui| {
                for opt in options {
                    if ui
                        .selectable_value(current_value, opt.clone(), opt.as_str())
                        .changed()
                    {
                        changed = true;
                    }
                }
            });
        return changed;
    }
    false
}

/// Renders a progress bar.
pub fn progress_bar(progress: f32, _style: &Value) {
    if let Some(ui) = bridge::get_ui() {
        ui.add(egui::ProgressBar::new(progress));
    }
}

/// Renders a separator.
pub fn separator(_style: &Value) {
    if let Some(ui) = bridge::get_ui() {
        ui.separator();
    }
}

/// Closes the application window.
pub fn quit() {
    if let Some(ui) = bridge::get_ui() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// Renders a collapsing header.
pub fn collapsing<F>(title: &str, _style: &Value, children: F)
where
    F: FnOnce(),
{
    if let Some(ui) = bridge::get_ui() {
        ui.collapsing(title, |ui| {
            bridge::with_ui_context(ui, children);
        });
    }
}

/// Renders a scroll area.
pub fn scroll_area<F>(_style: &Value, children: F)
where
    F: FnOnce(),
{
    if let Some(ui) = bridge::get_ui() {
        egui::ScrollArea::vertical().show(ui, |ui| {
            bridge::with_ui_context(ui, children);
        });
    }
}

/// Renders a high-performance plot
pub fn plot(title: &str, options: &Value) {
    if let Some(ui) = bridge::get_ui() {
        let mut plot = Plot::new(title).legend(Legend::default());

        let mut height = 200.0;

        if let Value::Record(r) = options {
            let r = r.borrow();

            if let Some(Value::Number(h)) = r.get("height") {
                height = *h as f32;
            }
            if let Some(Value::String(x)) = r.get("x_label") {
                plot = plot.x_axis_label(x);
            }
            if let Some(Value::String(y)) = r.get("y_label") {
                plot = plot.y_axis_label(y);
            }

            if let Some(Value::Vector(series_vec)) = r.get("series") {
                let series_list = series_vec.borrow();

                plot.height(height).show(ui, |plot_ui| {
                    for series_val in series_list.iter() {
                        if let Value::Record(s) = series_val {
                            let s = s.borrow();
                            let name = s
                                .get("name")
                                .and_then(|v| match v {
                                    Value::String(n) => Some(n.clone()),
                                    _ => None,
                                })
                                .unwrap_or_default();

                            let color_str = s.get("color").and_then(|v| match v {
                                Value::String(c) => Some(c.clone()),
                                _ => None,
                            });

                            let data_val = s.get("data");
                            if let Some(data) = data_val {
                                let points = extract_plot_points(data);

                                // Check "type", "kind", or "mode" to avoid keyword conflicts in script
                                let type_val = s
                                    .get("type")
                                    .or_else(|| s.get("kind"))
                                    .or_else(|| s.get("mode"));

                                let type_str = type_val
                                    .and_then(|v| match v {
                                        Value::String(t) => Some(t.as_str()),
                                        _ => Some("line"),
                                    })
                                    .unwrap_or("line");

                                match type_str {
                                    "line" => {
                                        let mut line = Line::new(points).name(&name);
                                        if let Some(c) = &color_str {
                                            line = line.color(crate::style::parse_hex_color(c));
                                        }
                                        plot_ui.line(line);
                                    }
                                    "scatter" | "points" => {
                                        let mut pts = Points::new(points).name(&name);
                                        if let Some(c) = &color_str {
                                            pts = pts.color(crate::style::parse_hex_color(c));
                                        }
                                        if let Some(Value::Number(r)) = s.get("radius") {
                                            pts = pts.radius(*r as f32);
                                        }
                                        plot_ui.points(pts);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                });
                return;
            }
        }

        plot.height(height).show(ui, |_| {});
    }
}

/// Optimized extraction of points from Achronyme values
fn extract_plot_points(data: &Value) -> PlotPoints {
    // Case 1: Tensor (Fast Path)
    if let Value::Tensor(t) = data {
        let shape = t.shape();
        let raw_data = t.data();

        if shape.len() == 2 && shape[1] == 2 {
            let points: Vec<[f64; 2]> = raw_data
                .chunks_exact(2)
                .map(|chunk| [chunk[0], chunk[1]])
                .collect();
            return PlotPoints::new(points);
        } else if shape.len() == 1 {
            let points: Vec<[f64; 2]> = raw_data
                .iter()
                .enumerate()
                .map(|(i, &y)| [i as f64, y])
                .collect();
            return PlotPoints::new(points);
        }
    }

    // Case 2: Vector of Vectors
    if let Value::Vector(v_rc) = data {
        let v = v_rc.borrow();
        if let Some(first) = v.first() {
            if let Value::Vector(_) = first {
                let points: Vec<[f64; 2]> = v
                    .iter()
                    .filter_map(|item| {
                        if let Value::Vector(pair) = item {
                            let p = pair.borrow();
                            if p.len() >= 2 {
                                if let (Value::Number(x), Value::Number(y)) = (&p[0], &p[1]) {
                                    return Some([*x, *y]);
                                }
                            }
                        }
                        None
                    })
                    .collect();
                return PlotPoints::new(points);
            } else if let Value::Number(_) = first {
                let points: Vec<[f64; 2]> = v
                    .iter()
                    .enumerate()
                    .filter_map(|(i, item)| {
                        if let Value::Number(y) = item {
                            Some([i as f64, *y])
                        } else {
                            None
                        }
                    })
                    .collect();
                return PlotPoints::new(points);
            }
        }
    }

    PlotPoints::new(vec![])
}
