pub mod circuit;
pub mod compile;
pub mod disassemble;
pub mod run;

use compiler::{ColorMode, Compiler, CompilerError, DiagnosticRenderer};

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

/// Convert a CompilerError to a rendered diagnostic string with source snippets.
pub fn render_compile_error(err: &CompilerError, source: &str) -> String {
    let diag = err.to_diagnostic();
    let renderer = DiagnosticRenderer::new(source, ColorMode::Auto);
    renderer.render(&diag)
}
