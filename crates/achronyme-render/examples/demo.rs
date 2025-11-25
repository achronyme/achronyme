//! Demo: AUI Engine - Interactive buttons test
//!
//! Run with: cargo run -p achronyme-render --example demo
//!
//! This demo showcases:
//! - Tailwind-inspired style parser
//! - Hit testing and hover effects
//! - Click event handling

use achronyme_render::{run, AuiApp, WindowConfig};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

fn main() {
    let config = WindowConfig {
        title: "AUI Demo - Interactive Events".to_string(),
        width: 600,
        height: 400,
    };

    let mut app = AuiApp::new(config);

    // Shared counter for demonstrating click events
    let click_count = Arc::new(AtomicU32::new(0));

    // Root: full window, dark background, center children
    let root = app.add_container("flex-col items-center justify-center gap-5 bg-[#1a1a1a]");

    // Title
    let title = app.add_text("AUI Interactive Demo", "text-white w-[250px] h-[30px]");
    app.add_child(root, title);

    // Instruction text
    let instruction = app.add_text(
        "Hover over buttons to see effects!",
        "text-gray-400 w-[280px] h-[20px]",
    );
    app.add_child(root, instruction);

    // Card container
    let card = app.add_container("flex-col items-center p-6 gap-4 bg-[#333333] rounded-xl");
    app.add_child(root, card);

    // Row of interactive buttons
    let button_row = app.add_container("flex-row gap-3 items-center");
    app.add_child(card, button_row);

    // Button 1 - Red
    let btn1 = app.add_button("Red", "bg-red-500 rounded-lg w-[80px] h-[40px]");
    app.add_child(button_row, btn1);

    // Button 2 - Green
    let btn2 = app.add_button("Green", "bg-green-500 rounded-lg w-[80px] h-[40px]");
    app.add_child(button_row, btn2);

    // Button 3 - Blue
    let btn3 = app.add_button("Blue", "bg-blue-500 rounded-lg w-[80px] h-[40px]");
    app.add_child(button_row, btn3);

    // Main action button
    let main_btn = app.add_button("Click Me!", "bg-purple-500 rounded-xl w-[150px] h-[48px]");
    app.add_child(card, main_btn);

    // Register click handlers
    let count1 = click_count.clone();
    app.on_click(btn1, move |_evt| {
        let n = count1.fetch_add(1, Ordering::SeqCst) + 1;
        println!("Red button clicked! Total clicks: {}", n);
    });

    let count2 = click_count.clone();
    app.on_click(btn2, move |_evt| {
        let n = count2.fetch_add(1, Ordering::SeqCst) + 1;
        println!("Green button clicked! Total clicks: {}", n);
    });

    let count3 = click_count.clone();
    app.on_click(btn3, move |_evt| {
        let n = count3.fetch_add(1, Ordering::SeqCst) + 1;
        println!("Blue button clicked! Total clicks: {}", n);
    });

    let count_main = click_count.clone();
    app.on_click(main_btn, move |evt| {
        let n = count_main.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "Main button clicked at ({:.0}, {:.0})! Total clicks: {}",
            evt.local_x, evt.local_y, n
        );
    });

    // Row of colored boxes (non-interactive)
    let box_row = app.add_container("flex-row gap-2 items-center mt-4");
    app.add_child(root, box_row);

    let colors = ["bg-red-400", "bg-orange-400", "bg-yellow-400", "bg-green-400", "bg-blue-400", "bg-purple-400"];
    for color in colors {
        let style = format!("{} rounded w-[30px] h-[30px]", color);
        let box_node = app.add_container(&style);
        app.add_child(box_row, box_node);
    }

    // Footer
    let footer = app.add_text(
        "Check console for click events",
        "text-gray-500 w-[220px] h-[20px]",
    );
    app.add_child(root, footer);

    app.set_root(root);

    println!("AUI Interactive Demo");
    println!("====================");
    println!("- Hover over buttons to see highlight effect");
    println!("- Click buttons to see press effect and console output");
    println!("- Window: 600x400");
    println!();

    run(app);
}
