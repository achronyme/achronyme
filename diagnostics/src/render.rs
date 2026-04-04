use crate::diagnostic::{Diagnostic, Severity, SpanRange};

/// ANSI color codes.
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Controls whether ANSI color codes are emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Always,
    Never,
    Auto,
}

impl ColorMode {
    /// Resolve to a concrete yes/no based on TTY detection.
    fn use_color(self) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => atty_stderr(),
        }
    }
}

/// Check if stderr is a TTY (without external crate dependency).
pub fn atty_stderr() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn isatty(fd: std::ffi::c_int) -> std::ffi::c_int;
        }
        unsafe { isatty(2) != 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Renders diagnostics with source snippets and optional ANSI colors.
pub struct DiagnosticRenderer<'a> {
    source: &'a str,
    lines: Vec<&'a str>,
    color: bool,
}

impl<'a> DiagnosticRenderer<'a> {
    pub fn new(source: &'a str, color_mode: ColorMode) -> Self {
        let lines: Vec<&str> = source.lines().collect();
        Self {
            source,
            lines,
            color: color_mode.use_color(),
        }
    }

    /// Render a diagnostic to a String.
    pub fn render(&self, diag: &Diagnostic) -> String {
        let mut out = String::new();
        self.render_to(&mut out, diag);
        out
    }

    /// Render a diagnostic, appending to the given String.
    pub fn render_to(&self, out: &mut String, diag: &Diagnostic) {
        let margin_width = self.margin_width(diag);

        // Header: error[E001]: message
        self.write_header(out, diag);

        // Location: --> file:line:col
        self.write_location(out, &diag.primary_span, margin_width);

        // Empty margin line
        self.write_margin(out, None, margin_width);
        out.push('\n');

        // Primary span with source snippet
        self.write_span_snippet(out, &diag.primary_span, None, diag.severity, margin_width);

        // Secondary labels
        for label in &diag.labels {
            self.write_margin(out, None, margin_width);
            out.push('\n');
            self.write_span_snippet(
                out,
                &label.span,
                Some(&label.message),
                Severity::Note,
                margin_width,
            );
        }

        // Trailing empty margin
        self.write_margin(out, None, margin_width);
        out.push('\n');

        // Notes
        for note in &diag.notes {
            self.write_footer_line(out, "note", note, margin_width);
        }

        // Suggestions
        for suggestion in &diag.suggestions {
            self.write_footer_line(out, "help", &suggestion.message, margin_width);
        }
    }

    fn write_header(&self, out: &mut String, diag: &Diagnostic) {
        let (color, reset, bold) = if self.color {
            (self.severity_color(diag.severity), ansi::RESET, ansi::BOLD)
        } else {
            ("", "", "")
        };

        out.push_str(bold);
        out.push_str(color);
        out.push_str(&diag.severity.to_string());
        if let Some(code) = &diag.code {
            out.push('[');
            out.push_str(code);
            out.push(']');
        }
        out.push_str(": ");
        out.push_str(reset);
        out.push_str(bold);
        out.push_str(&diag.message);
        out.push_str(reset);
        out.push('\n');
    }

    fn write_location(&self, out: &mut String, span: &SpanRange, margin_width: usize) {
        let (blue, reset) = if self.color {
            (ansi::BLUE, ansi::RESET)
        } else {
            ("", "")
        };

        for _ in 0..margin_width {
            out.push(' ');
        }
        out.push_str(blue);
        out.push_str(" --> ");
        out.push_str(reset);

        if let Some(file) = &span.file {
            out.push_str(&file.display().to_string());
            out.push(':');
        }
        out.push_str(&span.line_start.to_string());
        out.push(':');
        out.push_str(&span.col_start.to_string());
        out.push('\n');
    }

    fn write_margin(&self, out: &mut String, line_num: Option<usize>, margin_width: usize) {
        let (blue, reset) = if self.color {
            (ansi::BLUE, ansi::RESET)
        } else {
            ("", "")
        };

        out.push_str(blue);
        match line_num {
            Some(n) => {
                let s = n.to_string();
                for _ in 0..(margin_width - s.len()) {
                    out.push(' ');
                }
                out.push_str(&s);
                out.push_str(" | ");
            }
            None => {
                for _ in 0..margin_width {
                    out.push(' ');
                }
                out.push_str(" | ");
            }
        }
        out.push_str(reset);
    }

    fn write_span_snippet(
        &self,
        out: &mut String,
        span: &SpanRange,
        label_msg: Option<&str>,
        severity: Severity,
        margin_width: usize,
    ) {
        if span.line_start == 0 || span.line_start > self.lines.len() {
            return;
        }

        let (color, reset, bold) = if self.color {
            (self.severity_color(severity), ansi::RESET, ansi::BOLD)
        } else {
            ("", "", "")
        };

        if span.line_start == span.line_end || span.line_end == 0 {
            // Single-line span
            let line_idx = span.line_start - 1;
            let line = self.lines.get(line_idx).copied().unwrap_or("");

            // Source line
            self.write_margin(out, Some(span.line_start), margin_width);
            out.push_str(line);
            out.push('\n');

            // Underline
            self.write_margin(out, None, margin_width);

            let col_start = span.col_start.saturating_sub(1);
            let span_len = if span.col_end > span.col_start {
                span.col_end - span.col_start
            } else {
                1
            };

            for _ in 0..col_start {
                out.push(' ');
            }
            out.push_str(bold);
            out.push_str(color);
            for _ in 0..span_len {
                out.push('^');
            }
            if let Some(msg) = label_msg {
                out.push(' ');
                out.push_str(msg);
            }
            out.push_str(reset);
            out.push('\n');
        } else {
            // Multi-line span
            let start_idx = span.line_start - 1;
            let end_idx = (span.line_end - 1).min(self.lines.len() - 1);

            for idx in start_idx..=end_idx {
                let line = self.lines.get(idx).copied().unwrap_or("");
                let line_num = idx + 1;

                self.write_margin(out, Some(line_num), margin_width);
                out.push_str(line);
                out.push('\n');

                // Underline for first and last line
                if idx == start_idx {
                    self.write_margin(out, None, margin_width);
                    let col_start = span.col_start.saturating_sub(1);
                    let underline_len = line.len().saturating_sub(col_start);
                    for _ in 0..col_start {
                        out.push(' ');
                    }
                    out.push_str(bold);
                    out.push_str(color);
                    for _ in 0..underline_len {
                        out.push('^');
                    }
                    out.push_str(reset);
                    out.push('\n');
                } else if idx == end_idx {
                    self.write_margin(out, None, margin_width);
                    let underline_len = if span.col_end > 1 {
                        span.col_end - 1
                    } else {
                        line.len()
                    };
                    out.push_str(bold);
                    out.push_str(color);
                    for _ in 0..underline_len {
                        out.push('^');
                    }
                    if let Some(msg) = label_msg {
                        out.push(' ');
                        out.push_str(msg);
                    }
                    out.push_str(reset);
                    out.push('\n');
                }
            }
        }
    }

    fn write_footer_line(&self, out: &mut String, kind: &str, message: &str, margin_width: usize) {
        let (color, reset, bold) = if self.color {
            let c = match kind {
                "note" => ansi::BLUE,
                "help" => ansi::CYAN,
                _ => "",
            };
            (c, ansi::RESET, ansi::BOLD)
        } else {
            ("", "", "")
        };

        for _ in 0..margin_width {
            out.push(' ');
        }
        out.push_str(" = ");
        out.push_str(bold);
        out.push_str(color);
        out.push_str(kind);
        out.push_str(": ");
        out.push_str(reset);
        out.push_str(message);
        out.push('\n');
    }

    fn severity_color(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Error => ansi::RED,
            Severity::Warning => ansi::YELLOW,
            Severity::Note => ansi::BLUE,
            Severity::Help => ansi::CYAN,
        }
    }

    /// Calculate margin width (enough digits for the largest line number).
    fn margin_width(&self, diag: &Diagnostic) -> usize {
        let mut max_line = diag.primary_span.line_end;
        for label in &diag.labels {
            max_line = max_line.max(label.span.line_end);
        }
        if max_line == 0 {
            max_line = 1;
        }
        max_line.to_string().len()
    }

    /// Access to source (for callers that need it).
    pub fn source(&self) -> &str {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_plain(source: &str, diag: &Diagnostic) -> String {
        DiagnosticRenderer::new(source, ColorMode::Never).render(diag)
    }

    #[test]
    fn single_line_error() {
        let source = "let x = 1 ++ 2";
        let diag = Diagnostic::error("expected expression", SpanRange::new(10, 12, 1, 11, 1, 13));
        let output = render_plain(source, &diag);
        assert!(output.contains("error: expected expression"));
        assert!(output.contains("1:11"));
        assert!(output.contains("let x = 1 ++ 2"));
        assert!(output.contains("^^"));
    }

    #[test]
    fn error_with_code() {
        let source = "let x: u32 = \"hello\"";
        let diag = Diagnostic::error("type mismatch", SpanRange::new(13, 20, 1, 14, 1, 21))
            .with_code("E001");
        let output = render_plain(source, &diag);
        assert!(output.contains("error[E001]: type mismatch"));
        assert!(output.contains("^^^^^^^"));
    }

    #[test]
    fn error_with_note_and_help() {
        let source = "let x = true + 1";
        let diag = Diagnostic::error("type mismatch", SpanRange::new(8, 12, 1, 9, 1, 13))
            .with_note("cannot add Bool and Int")
            .with_suggestion(
                SpanRange::new(8, 12, 1, 9, 1, 13),
                "to_int(x)",
                "convert to integer first",
            );
        let output = render_plain(source, &diag);
        assert!(output.contains("= note: cannot add Bool and Int"));
        assert!(output.contains("= help: convert to integer first"));
    }

    #[test]
    fn point_span_single_caret() {
        let source = "let x = ;";
        let diag = Diagnostic::error("expected expression", SpanRange::point(1, 9, 8));
        let output = render_plain(source, &diag);
        assert!(output.contains("^"));
        let underline_line = output.lines().find(|l| l.contains('^')).unwrap();
        assert_eq!(underline_line.matches('^').count(), 1);
    }
}
