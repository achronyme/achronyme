use achronyme_lsp_core::get_signature;
use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Get signature help for a position in the document
pub fn get_signature_help(doc: &Document, position: Position) -> Option<SignatureHelp> {
    let text = doc.text();
    let offset = doc.offset_from_position(position.line, position.character);

    // Find the function call we're inside
    let (func_name, param_index) = find_function_call_context(text, offset)?;

    // Get the function signature from the shared core crate
    let func_sig = get_signature(&func_name)?;

    // Build LSP SignatureHelp
    let parameters: Vec<ParameterInformation> = func_sig
        .parameters
        .iter()
        .map(|p| ParameterInformation {
            label: ParameterLabel::Simple(p.label.clone()),
            documentation: Some(Documentation::String(p.documentation.clone())),
        })
        .collect();

    let signature_info = SignatureInformation {
        label: func_sig.signature.clone(),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::Markdown,
            value: func_sig.documentation.clone(),
        })),
        parameters: Some(parameters),
        active_parameter: Some(param_index as u32),
    };

    Some(SignatureHelp {
        signatures: vec![signature_info],
        active_signature: Some(0),
        active_parameter: Some(param_index as u32),
    })
}

/// Find the function name and active parameter index at the cursor position
fn find_function_call_context(text: &str, cursor_offset: usize) -> Option<(String, usize)> {
    let chars: Vec<char> = text.chars().collect();
    let cursor = cursor_offset.min(chars.len());

    // Search backwards from cursor to find the opening parenthesis
    let mut depth = 0;
    let mut paren_pos = None;

    for i in (0..cursor).rev() {
        match chars[i] {
            ')' => depth += 1,
            '(' => {
                if depth == 0 {
                    paren_pos = Some(i);
                    break;
                } else {
                    depth -= 1;
                }
            }
            _ => {}
        }
    }

    let open_paren = paren_pos?;

    // Extract function name (immediately before the opening parenthesis)
    let mut func_end = open_paren;
    while func_end > 0 && chars[func_end - 1].is_whitespace() {
        func_end -= 1;
    }

    let mut func_start = func_end;
    while func_start > 0 && is_identifier_char(chars[func_start - 1]) {
        func_start -= 1;
    }

    if func_start >= func_end {
        return None;
    }

    let func_name: String = chars[func_start..func_end].iter().collect();

    // Count parameters (commas) to determine active parameter
    let param_index = count_parameters_before_cursor(text, open_paren, cursor);

    Some((func_name, param_index))
}

/// Count the number of commas (parameters) before the cursor, respecting nesting
fn count_parameters_before_cursor(text: &str, func_start: usize, cursor: usize) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut count = 0;
    let mut depth = 0;
    let mut in_string = false;
    let mut in_lambda = false;
    let mut escape_next = false;

    // Start after the opening parenthesis
    let start = func_start + 1;
    let end = cursor.min(chars.len());

    for ch in chars.iter().take(end).skip(start) {
        if escape_next {
            escape_next = false;
            continue;
        }

        if *ch == '\\' && in_string {
            escape_next = true;
            continue;
        }

        match *ch {
            '"' => in_string = !in_string,
            '|' if !in_string => {
                // Toggle lambda state (|params| body)
                in_lambda = !in_lambda;
            }
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if !in_string && depth == 0 && !in_lambda => count += 1,
            _ => {}
        }
    }

    count
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_function_call_simple() {
        let text = "sin(";
        let result = find_function_call_context(text, 4);
        assert_eq!(result, Some(("sin".to_string(), 0)));
    }

    #[test]
    fn test_find_function_call_with_first_arg() {
        let text = "pow(2, ";
        let result = find_function_call_context(text, 7);
        assert_eq!(result, Some(("pow".to_string(), 1)));
    }

    #[test]
    fn test_find_function_call_with_partial_arg() {
        let text = "map(x => x^2, ";
        let result = find_function_call_context(text, 14);
        assert_eq!(result, Some(("map".to_string(), 1)));
    }

    #[test]
    fn test_find_function_call_nested() {
        let text = "pow(sin(x), ";
        let result = find_function_call_context(text, 12);
        assert_eq!(result, Some(("pow".to_string(), 1)));
    }

    #[test]
    fn test_count_parameters_simple() {
        let text = "func(a, b, ";
        let count = count_parameters_before_cursor(text, 4, 11);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_parameters_with_nested_calls() {
        let text = "func(sin(x), cos(y), ";
        let count = count_parameters_before_cursor(text, 4, 21);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_parameters_with_string_commas() {
        let text = r#"func("a,b,c", "#;
        let count = count_parameters_before_cursor(text, 4, 14);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_parameters_with_array() {
        let text = "func([1, 2, 3], ";
        let count = count_parameters_before_cursor(text, 4, 16);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_function_signature_sin() {
        let sig = get_signature("sin");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.name, "sin");
        assert_eq!(sig.signature, "sin(x: Number) -> Number");
        assert_eq!(sig.parameters.len(), 1);
    }

    #[test]
    fn test_get_function_signature_pow() {
        let sig = get_signature("pow");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].label, "base: Number");
        assert_eq!(sig.parameters[1].label, "exp: Number");
    }

    #[test]
    fn test_get_function_signature_reduce() {
        let sig = get_signature("reduce");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.parameters.len(), 3);
    }

    #[test]
    fn test_get_function_signature_unknown() {
        let sig = get_signature("unknown_function");
        assert!(sig.is_none());
    }

    #[test]
    fn test_signature_help_document() {
        let doc = Document::new("sin(".to_string());
        let position = Position {
            line: 0,
            character: 4,
        };
        let help = get_signature_help(&doc, position);
        assert!(help.is_some());
        let help = help.unwrap();
        assert_eq!(help.signatures.len(), 1);
        assert_eq!(help.active_parameter, Some(0));
    }

    #[test]
    fn test_signature_help_second_parameter() {
        let doc = Document::new("pow(2, ".to_string());
        let position = Position {
            line: 0,
            character: 7,
        };
        let help = get_signature_help(&doc, position);
        assert!(help.is_some());
        let help = help.unwrap();
        assert_eq!(help.active_parameter, Some(1));
    }

    #[test]
    fn test_signature_help_multiline() {
        // Text: "let result = reduce(\n  |acc, x| acc + x,\n  "
        // The lambda has a comma inside it, but it's inside pipe characters
        // We have: reduce( followed by lambda (with internal comma ignored), then actual comma
        // So we've passed 1 comma at the outer level
        let doc = Document::new("let result = reduce(\n  |acc, x| acc + x,\n  ".to_string());
        let position = Position {
            line: 2,
            character: 2,
        };
        let help = get_signature_help(&doc, position);
        assert!(help.is_some());
        let help = help.unwrap();
        // After the lambda and one comma, we're on the second parameter (index 1)
        // Lambda commas are now properly ignored
        assert_eq!(help.active_parameter, Some(1));
    }

    #[test]
    fn test_escape_in_string() {
        let text = r#"func("a\"b,c", "#;
        let count = count_parameters_before_cursor(text, 4, 15);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_parameters_with_lambda() {
        // Lambda parameters should be ignored
        let text = "map(|x, y| x + y, ";
        let count = count_parameters_before_cursor(text, 3, 18);
        assert_eq!(count, 1); // Only one comma outside the lambda
    }

    #[test]
    fn test_find_function_call_with_spaces() {
        let text = "  sin  (  ";
        let result = find_function_call_context(text, 10);
        assert_eq!(result, Some(("sin".to_string(), 0)));
    }

    #[test]
    fn test_third_parameter() {
        let doc = Document::new("reduce(fn, arr, ".to_string());
        let position = Position {
            line: 0,
            character: 16,
        };
        let help = get_signature_help(&doc, position);
        assert!(help.is_some());
        let help = help.unwrap();
        assert_eq!(help.active_parameter, Some(2));
    }
}
