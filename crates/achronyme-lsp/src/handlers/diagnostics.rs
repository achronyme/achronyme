use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Compute diagnostics for a document by parsing it
pub fn compute_diagnostics(doc: &Document) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if let Some(error) = doc.parse_error() {
        // Parse the error message to extract position information
        let (line, character, message) = parse_error_message(error);

        diagnostics.push(Diagnostic {
            range: Range {
                start: Position { line, character },
                end: Position {
                    line,
                    character: character + 1,
                },
            },
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(NumberOrString::String("parse-error".to_string())),
            source: Some("achronyme".to_string()),
            message,
            ..Default::default()
        });
    }

    diagnostics
}

/// Parse error message to extract position (line, column) and clean message
/// Pest error messages typically contain position information like:
/// "Parse error:  --> 1:10\n  |\n1 | let x = ;\n  |          ^---"
fn parse_error_message(error: &str) -> (u32, u32, String) {
    let mut line = 0u32;
    let mut character = 0u32;
    let message = error.to_string();

    // Try to extract position from Pest error format
    // Format: " --> line:column"
    if let Some(pos_start) = error.find(" --> ") {
        let pos_str = &error[pos_start + 5..];
        if let Some(colon_pos) = pos_str.find(':') {
            let line_str = &pos_str[..colon_pos];
            let rest = &pos_str[colon_pos + 1..];

            // Find end of column number (usually newline or end of string)
            let col_end = rest.find('\n').unwrap_or(rest.len());
            let col_str = &rest[..col_end];

            if let Ok(l) = line_str.trim().parse::<u32>() {
                line = l.saturating_sub(1); // LSP uses 0-based line numbers
            }
            if let Ok(c) = col_str.trim().parse::<u32>() {
                character = c.saturating_sub(1); // LSP uses 0-based columns
            }
        }
    }

    (line, character, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_message() {
        let error = "Parse error:  --> 2:10\n  |\n2 | let x = ;\n  |          ^---";
        let (line, col, _msg) = parse_error_message(error);
        assert_eq!(line, 1); // 0-based
        assert_eq!(col, 9); // 0-based
    }
}
