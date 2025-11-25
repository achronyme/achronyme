//! Demo: AUI Engine - Shrink-wrap centering test
//!
//! Run with: cargo run -p achronyme-render --example demo
//!
//! This demo showcases the Tailwind-inspired style parser

use achronyme_render::{run, AuiApp, WindowConfig};

fn main() {
    let config = WindowConfig {
        title: "AUI Demo - Tailwind Styles".to_string(),
        width: 600,
        height: 400,
    };

    let mut app = AuiApp::new(config);

    // Root: full window, dark background, center children
    let root = app.add_container("flex-col items-center justify-center gap-5 bg-[#1a1a1a]");

    // Title
    let title = app.add_text("AUI Engine Demo", "text-white w-[200px] h-[30px]");
    app.add_child(root, title);

    // Card - NO explicit width (shrink-wrap!)
    // This is THE test: it should be centered, not left-aligned
    let card = app.add_container("flex-col items-center p-6 gap-4 bg-[#333333] rounded-xl");
    app.add_child(root, card);

    // Card content
    let label1 = app.add_text(
        "This card has NO explicit width",
        "text-gray-400 w-[220px] h-[20px]",
    );
    app.add_child(card, label1);

    let label2 = app.add_text(
        "It shrink-wraps to content",
        "text-gray-400 w-[180px] h-[20px]",
    );
    app.add_child(card, label2);

    let label3 = app.add_text(
        "AND stays centered!",
        "text-emerald-400 w-[150px] h-[24px]",
    );
    app.add_child(card, label3);

    // Button inside card
    let button = app.add_button("Click Me", "bg-blue-500 rounded-md w-[120px] h-[36px]");
    app.add_child(card, button);

    // Row of boxes (to test flex-row)
    let row = app.add_container("flex-row gap-3 items-center");
    app.add_child(root, row);

    // Three colored boxes
    let box1 = app.add_container("bg-red-500 rounded w-[50px] h-[50px]");
    app.add_child(row, box1);

    let box2 = app.add_container("bg-green-500 rounded w-[50px] h-[50px]");
    app.add_child(row, box2);

    let box3 = app.add_container("bg-blue-500 rounded w-[50px] h-[50px]");
    app.add_child(row, box3);

    // Footer
    let footer = app.add_text("egui couldn't do this!", "text-gray-500 w-[180px] h-[20px]");
    app.add_child(root, footer);

    app.set_root(root);

    println!("🚀 AUI Demo starting...");
    println!("   - Window: 600x400");
    println!("   - Testing: Tailwind-style CSS classes with Pest parser");

    run(app);
}
