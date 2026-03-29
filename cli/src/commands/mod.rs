pub mod circuit;
pub mod compile;
pub mod disassemble;
pub mod inspect;
pub mod run;

use compiler::{ColorMode, Compiler, CompilerError, Diagnostic, DiagnosticRenderer};

/// Create a compiler with std natives pre-registered.
pub fn new_compiler() -> Compiler {
    let std_table = achronyme_std::std_native_table();
    Compiler::with_extra_natives(&std_table)
}

/// Register std modules on a VM (call after `VM::new()`).
pub fn register_std_modules(vm: &mut vm::VM) -> Result<(), vm::error::RuntimeError> {
    for module in achronyme_std::std_modules() {
        vm.register_module(&*module)?;
    }
    Ok(())
}

/// Output format for compiler diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorFormat {
    /// Rich output with source snippets and colors (default)
    Human,
    /// JSON Lines — one JSON object per diagnostic (machine-readable)
    Json,
    /// Compact `file:line:col: severity: message` (grep-friendly)
    Short,
}

/// Emit any compiler warnings to stderr in the requested format.
pub fn print_warnings(compiler: &mut Compiler, source: &str, fmt: ErrorFormat) {
    let warnings = compiler.take_warnings();
    if warnings.is_empty() {
        return;
    }
    for w in &warnings {
        emit_diagnostic(w, source, fmt);
    }
}

/// Convert a CompilerError to a rendered diagnostic string.
pub fn render_compile_error(err: &CompilerError, source: &str, fmt: ErrorFormat) -> String {
    let diag = err.to_diagnostic();
    render_diagnostic(&diag, source, fmt)
}

/// Render a single diagnostic to a string in the requested format.
pub(super) fn render_diagnostic(diag: &Diagnostic, source: &str, fmt: ErrorFormat) -> String {
    match fmt {
        ErrorFormat::Human => {
            let renderer = DiagnosticRenderer::new(source, ColorMode::Auto);
            renderer.render(diag)
        }
        ErrorFormat::Json => diagnostic_to_json(diag),
        ErrorFormat::Short => diagnostic_to_short(diag),
    }
}

/// Emit a single diagnostic to stderr.
pub(super) fn emit_diagnostic(diag: &Diagnostic, source: &str, fmt: ErrorFormat) {
    eprintln!("{}", render_diagnostic(diag, source, fmt));
}

/// Format a diagnostic as a single JSON line (JSON Lines format).
fn diagnostic_to_json(diag: &Diagnostic) -> String {
    let mut labeled_spans: Vec<serde_json::Value> = Vec::new();
    // Primary span
    labeled_spans.push(span_to_json(&diag.primary_span, Some("primary")));
    // Secondary labels
    for label in &diag.labels {
        labeled_spans.push(span_to_json(&label.span, Some(&label.message)));
    }

    let suggestions: Vec<serde_json::Value> = diag
        .suggestions
        .iter()
        .map(|s| {
            serde_json::json!({
                "span": span_to_json(&s.span, None),
                "replacement": s.replacement,
                "message": s.message,
            })
        })
        .collect();

    let obj = serde_json::json!({
        "message": diag.message,
        "code": diag.code,
        "level": format!("{}", diag.severity),
        "spans": labeled_spans,
        "notes": diag.notes,
        "suggestions": suggestions,
    });

    // serde_json::to_string produces a single line (no pretty-print)
    serde_json::to_string(&obj)
        .unwrap_or_else(|_| serde_json::json!({"message": diag.message}).to_string())
}

fn span_to_json(span: &compiler::diagnostic::SpanRange, label: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "file_name": span.file.as_ref().map(|p| p.display().to_string()),
        "byte_start": span.byte_start,
        "byte_end": span.byte_end,
        "line_start": span.line_start,
        "line_end": span.line_end,
        "column_start": span.col_start,
        "column_end": span.col_end,
        "label": label,
    })
}

/// Format a diagnostic in short format: `file:line:col: severity: message`
fn diagnostic_to_short(diag: &Diagnostic) -> String {
    let span = &diag.primary_span;
    let file = span
        .file
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<stdin>".to_string());
    format!(
        "{}:{}:{}: {}: {}",
        file, span.line_start, span.col_start, diag.severity, diag.message
    )
}
