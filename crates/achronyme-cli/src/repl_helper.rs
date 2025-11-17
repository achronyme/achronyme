use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Helper};
use std::borrow::Cow;

use achronyme_lsp_core::get_signature;
use crate::highlighter::highlight_code;
use crate::lsp_completer::LspCompleter;

pub struct ReplHelper {
    completer: LspCompleter,
}

impl ReplHelper {
    pub fn new() -> Self {
        Self {
            completer: LspCompleter::new(),
        }
    }

    fn get_signature_hint(&self, line: &str, pos: usize) -> Option<String> {
        // Find if we're inside a function call
        let (func_name, param_index) = find_function_call_context(line, pos)?;

        // Get signature from lsp-core
        let sig = get_signature(&func_name)?;

        // Format hint with active parameter highlighted
        let params: Vec<String> = sig
            .parameters
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i == param_index {
                    format!(">{}<", p.label) // Highlight active param
                } else {
                    p.label.clone()
                }
            })
            .collect();

        Some(format!(
            " // {}({}) -> {}",
            func_name,
            params.join(", "),
            sig.signature.split("->").last().unwrap_or("").trim()
        ))
    }
}

impl Helper for ReplHelper {}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        self.completer.complete(line, pos, ctx)
    }
}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<Self::Hint> {
        // First check for function call context
        if let Some(sig_hint) = self.get_signature_hint(line, pos) {
            return Some(sig_hint);
        }

        // Fall back to completion hint
        self.completer.hint(line, pos, ctx)
    }
}

impl Highlighter for ReplHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Owned(highlight_code(line))
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        // Only highlight when forced (e.g., after Enter or specific triggers)
        // This prevents excessive highlighting on every character
        _forced
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Style hints in gray
        Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }
}

impl Validator for ReplHelper {
    fn validate(&self, ctx: &mut ValidationContext) -> rustyline::Result<ValidationResult> {
        let input = ctx.input();

        // Skip validation for special commands
        let trimmed = input.trim();
        if trimmed.is_empty()
            || trimmed == "exit"
            || trimmed == "quit"
            || trimmed == "help"
            || trimmed == "clear"
            || trimmed == "cls"
        {
            return Ok(ValidationResult::Valid(None));
        }

        // Check balanced delimiters first (fast check)
        if !has_balanced_delimiters(input) {
            return Ok(ValidationResult::Incomplete);
        }

        // Try parsing
        match achronyme_parser::parse(input) {
            Ok(_) => Ok(ValidationResult::Valid(None)),
            Err(e) => {
                let error_msg = e.to_string();

                // If it's an "expected EOI" error, input might be incomplete
                if error_msg.contains("expected") && error_msg.contains("EOI") {
                    Ok(ValidationResult::Incomplete)
                } else {
                    // Real parse error - show it
                    Ok(ValidationResult::Invalid(Some(format!(
                        "\n  ! Parse error: {}",
                        extract_short_error(&error_msg)
                    ))))
                }
            }
        }
    }
}

fn find_function_call_context(line: &str, pos: usize) -> Option<(String, usize)> {
    let before_cursor = &line[..pos];

    // Find the innermost unclosed parenthesis
    let mut depth = 0;
    let mut last_open_paren = None;
    let mut in_string = false;

    for (i, ch) in before_cursor.chars().enumerate() {
        match ch {
            '"' if !in_string => in_string = true,
            '"' if in_string => in_string = false,
            '(' if !in_string => {
                depth += 1;
                last_open_paren = Some(i);
            }
            ')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    last_open_paren = None;
                }
            }
            _ => {}
        }
    }

    let paren_pos = last_open_paren?;

    // Extract function name before the parenthesis
    let before_paren = &before_cursor[..paren_pos];
    let func_name = before_paren
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .last()?
        .to_string();

    if func_name.is_empty() {
        return None;
    }

    // Count commas to determine active parameter
    let inside_parens = &before_cursor[paren_pos + 1..];
    let param_index = count_parameters(inside_parens);

    Some((func_name, param_index))
}

fn count_parameters(text: &str) -> usize {
    let mut count = 0;
    let mut depth = 0;
    let mut in_string = false;

    for ch in text.chars() {
        match ch {
            '"' if !in_string => in_string = true,
            '"' if in_string => in_string = false,
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => depth -= 1,
            ',' if !in_string && depth == 0 => count += 1,
            _ => {}
        }
    }

    count
}

fn extract_short_error(error: &str) -> String {
    // Extract just the relevant part of the error
    if let Some(pos) = error.find("expected") {
        let end = error[pos..].find('\n').unwrap_or(error.len() - pos);
        error[pos..pos + end].to_string()
    } else {
        error.lines().next().unwrap_or(error).to_string()
    }
}

fn has_balanced_delimiters(input: &str) -> bool {
    let mut paren_count = 0i32;
    let mut bracket_count = 0i32;
    let mut brace_count = 0i32;
    let mut in_string = false;

    for ch in input.chars() {
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => paren_count += 1,
            ')' if !in_string => paren_count -= 1,
            '[' if !in_string => bracket_count += 1,
            ']' if !in_string => bracket_count -= 1,
            '{' if !in_string => brace_count += 1,
            '}' if !in_string => brace_count -= 1,
            _ => {}
        }

        if paren_count < 0 || bracket_count < 0 || brace_count < 0 {
            return false;
        }
    }

    paren_count == 0 && bracket_count == 0 && brace_count == 0 && !in_string
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_function_call_context_simple() {
        let line = "sin(";
        let result = find_function_call_context(line, 4);
        assert_eq!(result, Some(("sin".to_string(), 0)));
    }

    #[test]
    fn test_find_function_call_context_with_arg() {
        let line = "sin(PI / 2";
        let result = find_function_call_context(line, 10);
        assert_eq!(result, Some(("sin".to_string(), 0)));
    }

    #[test]
    fn test_find_function_call_context_second_param() {
        let line = "map([1,2,3], ";
        let result = find_function_call_context(line, 13);
        assert_eq!(result, Some(("map".to_string(), 1)));
    }

    #[test]
    fn test_find_function_call_context_third_param() {
        let line = "reduce([1,2,3], 0, ";
        let result = find_function_call_context(line, 19);
        assert_eq!(result, Some(("reduce".to_string(), 2)));
    }

    #[test]
    fn test_find_function_call_context_nested() {
        let line = "map(filter(arr, ";
        let result = find_function_call_context(line, 16);
        // Should find the innermost function (filter)
        assert_eq!(result, Some(("filter".to_string(), 1)));
    }

    #[test]
    fn test_find_function_call_context_no_function() {
        let line = "let x = 5";
        let result = find_function_call_context(line, 9);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_function_call_context_closed_paren() {
        let line = "sin(x) + cos(";
        let result = find_function_call_context(line, 13);
        // Should find cos as the active function
        assert_eq!(result, Some(("cos".to_string(), 0)));
    }

    #[test]
    fn test_count_parameters_none() {
        assert_eq!(count_parameters(""), 0);
        assert_eq!(count_parameters("x"), 0);
    }

    #[test]
    fn test_count_parameters_one_comma() {
        assert_eq!(count_parameters("x, "), 1);
        assert_eq!(count_parameters("[1,2,3], "), 1);
    }

    #[test]
    fn test_count_parameters_two_commas() {
        assert_eq!(count_parameters("x, y, "), 2);
    }

    #[test]
    fn test_count_parameters_nested_commas() {
        // Commas inside nested structures shouldn't count
        assert_eq!(count_parameters("[1,2,3], [4,5,6], "), 2);
        assert_eq!(count_parameters("func(a, b), "), 1);
    }

    #[test]
    fn test_count_parameters_string_commas() {
        // Commas inside strings shouldn't count
        assert_eq!(count_parameters("\"a,b,c\", "), 1);
    }

    #[test]
    fn test_has_balanced_delimiters_balanced() {
        assert!(has_balanced_delimiters("()"));
        assert!(has_balanced_delimiters("[]"));
        assert!(has_balanced_delimiters("{}"));
        assert!(has_balanced_delimiters("let x = [1, 2, 3]"));
        assert!(has_balanced_delimiters("func(a, b)"));
        assert!(has_balanced_delimiters("{ a: 1, b: 2 }"));
    }

    #[test]
    fn test_has_balanced_delimiters_unbalanced() {
        assert!(!has_balanced_delimiters("("));
        assert!(!has_balanced_delimiters("["));
        assert!(!has_balanced_delimiters("{"));
        assert!(!has_balanced_delimiters("sin(x"));
        assert!(!has_balanced_delimiters("[1, 2, 3"));
    }

    #[test]
    fn test_has_balanced_delimiters_in_string() {
        // Delimiters inside strings should be ignored
        assert!(has_balanced_delimiters("\"(\""));
        assert!(has_balanced_delimiters("let s = \"[test]\""));
        // Unclosed string
        assert!(!has_balanced_delimiters("\"unclosed"));
    }

    #[test]
    fn test_extract_short_error_with_expected() {
        let error = "  --> 1:10\n  |\n1 | let x = (\n  |          ^---\n  |\n  = expected expression";
        let result = extract_short_error(error);
        assert!(result.contains("expected"));
    }

    #[test]
    fn test_extract_short_error_single_line() {
        let error = "Syntax error at line 1";
        let result = extract_short_error(error);
        assert_eq!(result, "Syntax error at line 1");
    }

    #[test]
    fn test_signature_hint_sin() {
        let helper = ReplHelper::new();
        let line = "sin(";
        let hint = helper.get_signature_hint(line, 4);
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(hint.contains("sin"));
        assert!(hint.contains(">x: Number<")); // Active param highlighted
        assert!(hint.contains("Number")); // Return type
    }

    #[test]
    fn test_signature_hint_map_second_param() {
        let helper = ReplHelper::new();
        let line = "map([1,2,3], ";
        let hint = helper.get_signature_hint(line, 13);
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(hint.contains("map"));
        assert!(hint.contains("arr: Array")); // First param not highlighted
        assert!(hint.contains(">fn: Function<")); // Second param highlighted
    }

    #[test]
    fn test_signature_hint_unknown_function() {
        let helper = ReplHelper::new();
        let line = "unknown_func(";
        let hint = helper.get_signature_hint(line, 13);
        assert!(hint.is_none());
    }
}
