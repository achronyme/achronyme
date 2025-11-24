use crate::bridge;
use achronyme_types::value::Value;
pub use eframe;
pub use eframe::egui;
use std::rc::Rc;

/// A trait that abstracts the capability to call an Achronyme function.
/// This allows passing the VM's execution logic into the GUI runner
/// without depending on achronyme-vm directly.
pub trait Evaluator: 'static {
    fn call(&self, func: &Value, args: Vec<Value>) -> Result<Value, anyhow::Error>;
}

pub struct AchronymeApp {
    /// The user-defined render function: `(ui) => { ... }`
    render_fn: Value,
    /// The evaluator (VM wrapper)
    evaluator: Rc<Box<dyn Evaluator>>,
}

impl AchronymeApp {
    pub fn new(render_fn: Value, evaluator: Rc<Box<dyn Evaluator>>) -> Self {
        Self {
            render_fn,
            evaluator,
        }
    }
}

impl eframe::App for AchronymeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Bridge the UI context so native functions can use it
            bridge::with_ui_context(ui, || {
                // Construct the 'ui' object to pass to the script
                // For now, we pass Null or an empty record,
                // as the functions will use the thread-local context anyway.
                // In the future, this Record can hold specific helpers.
                let ui_arg = Value::Null;

                // Execute the script's render function
                // We ignore errors for now in the render loop to avoid crashing
                let _ = self.evaluator.call(&self.render_fn, vec![ui_arg]);
            });
        });

        // Request constant repaint for animations and async signal updates
        ctx.request_repaint();
    }
}

pub fn run_native(
    app_name: &str,
    render_fn: Value,
    evaluator: Box<dyn Evaluator>,
    options: eframe::NativeOptions, // Add this parameter
) -> eframe::Result<()> {
    let evaluator_rc = Rc::new(evaluator);

    eframe::run_native(
        app_name,
        options, // Use passed options
        Box::new(move |cc| {
            setup_custom_fonts(&cc.egui_ctx);
            Ok(Box::new(AchronymeApp::new(render_fn, evaluator_rc)))
        }),
    )
}

fn setup_custom_fonts(ctx: &egui::Context) {
    ctx.set_visuals(egui::Visuals::dark());
}
