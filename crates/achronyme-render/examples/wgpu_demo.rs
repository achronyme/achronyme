//! Demo: Test the wgpu-based renderer
//!
//! Run with: cargo run -p achronyme-render --example wgpu_demo --features wgpu-backend

use achronyme_render::{run, AuiApp, WindowConfig};
use achronyme_render::node::{PlotSeries, PlotKind};

fn main() {
    let config = WindowConfig {
        title: "AUI wgpu Demo".to_string(),
        width: 800,
        height: 600,
    };

    let mut app = AuiApp::new(config);

    // Root container - dark background, centered content
    let root = app.add_container("bg-[#1a1a2e] w-full h-full flex-col items-center justify-center gap-8");

    // Title
    let title = app.add_text("Achronyme UI Engine", "text-white text-2xl");
    app.add_child(root, title);

    // Subtitle
    let subtitle = app.add_text("GPU Accelerated with wgpu", "text-[#8888aa]");
    app.add_child(root, subtitle);

    // Card container
    let card = app.add_container("bg-[#16213e] rounded-lg p-6 flex-col gap-4 items-center");
    app.add_child(root, card);

    // Buttons row
    let button_row = app.add_container("flex-row gap-4");
    app.add_child(card, button_row);

    let btn1 = app.add_button(1, "Primary", "bg-[#0f3460] text-white px-4 py-2 rounded");
    app.add_child(button_row, btn1);

    let btn2 = app.add_button(2, "Secondary", "bg-[#e94560] text-white px-4 py-2 rounded");
    app.add_child(button_row, btn2);

    let btn3 = app.add_button(3, "Success", "bg-[#1a936f] text-white px-4 py-2 rounded");
    app.add_child(button_row, btn3);

    // Text Input
    let input_label = app.add_text("Name:", "text-white");
    app.add_child(card, input_label);

    let text_input = app.add_text_input(1, "Enter your name...", "", "w-[200px] h-[36px] rounded");
    app.add_child(card, text_input);

    // Slider
    let slider_label = app.add_text("Volume:", "text-white");
    app.add_child(card, slider_label);

    let slider = app.add_slider(2, 0.0, 100.0, 65.0, "w-[200px]");
    app.add_child(card, slider);

    // Checkbox
    let checkbox = app.add_checkbox(3, "Enable notifications", true, "text-white");
    app.add_child(card, checkbox);

    // Progress bar
    let progress_label = app.add_text("Download Progress:", "text-white");
    app.add_child(card, progress_label);

    let progress = app.add_progress_bar(0.75, "w-[200px] h-[8px] rounded bg-[#374151]");
    app.add_child(card, progress);

    // Separator
    let sep = app.add_separator("w-[250px] h-[1px] bg-[#4b5563]");
    app.add_child(card, sep);

    // Plot with line graph (sine wave)
    let sine_data: Vec<(f64, f64)> = (0..50)
        .map(|i| {
            let x = i as f64 * 0.2;
            let y = (x * 0.5).sin() * 50.0 + 50.0;
            (x, y)
        })
        .collect();

    let cosine_data: Vec<(f64, f64)> = (0..50)
        .map(|i| {
            let x = i as f64 * 0.2;
            let y = (x * 0.5).cos() * 50.0 + 50.0;
            (x, y)
        })
        .collect();

    let plot = app.add_plot(
        "Sine & Cosine Waves",
        "Time",
        "Value",
        vec![
            PlotSeries {
                name: "Sine".to_string(),
                kind: PlotKind::Line,
                data: sine_data,
                color: 0xFF4ade80, // Green
                radius: 4.0,
            },
            PlotSeries {
                name: "Cosine".to_string(),
                kind: PlotKind::Line,
                data: cosine_data,
                color: 0xFF60a5fa, // Blue
                radius: 4.0,
            },
        ],
        "w-[350px] h-[200px]",
    );
    app.add_child(card, plot);

    // Footer text
    let footer = app.add_text("Powered by wgpu + Taffy", "text-[#6b7280]");
    app.add_child(card, footer);

    app.set_root(root);

    println!("Starting AUI wgpu demo...");
    println!("Backend: wgpu (GPU accelerated)");
    println!("Press Escape or close window to exit");

    run(app);
}
