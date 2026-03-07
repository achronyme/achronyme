pub mod circuit;
pub mod compile;
pub mod disassemble;
pub mod run;

use compiler::{ColorMode, Compiler, DiagnosticRenderer};

/// Render any compiler warnings to stderr.
pub fn print_warnings(compiler: &mut Compiler, source: &str) {
    let warnings = compiler.take_warnings();
    if warnings.is_empty() {
        return;
    }
    let renderer = DiagnosticRenderer::new(source, ColorMode::Auto);
    for w in &warnings {
        eprintln!("{}", renderer.render(w));
    }
}
