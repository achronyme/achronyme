/// Lint module for Achronyme code
/// Checks for parse errors and reports them with line/column information

use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LintError {
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub severity: String,
}

/// Check source code for parse errors
pub fn check_errors(source: &str) -> Vec<LintError> {
    let mut errors = Vec::new();

    // Try to parse the code
    match achronyme_parser::parse(source) {
        Ok(_) => {
            // No parse errors
        }
        Err(parse_error) => {
            // Extract error information
            let error_msg = parse_error.to_string();

            // Try to extract line and column information from the error message
            let (line, column) = extract_line_column_from_error(&error_msg, source);

            errors.push(LintError {
                line,
                column,
                message: error_msg.clone(),
                severity: "error".to_string(),
            });
        }
    }

    // Additional linting checks
    additional_checks(source, &mut errors);

    errors
}

/// Extract line and column from pest error message
fn extract_line_column_from_error(_error_msg: &str, source: &str) -> (usize, usize) {
    // Try to parse error message for line/column info
    // Pest errors typically contain position information
    // Format might be: " at line X, column Y" or similar

    // Default: find the position of "EOI" or last character
    let lines: Vec<&str> = source.lines().collect();

    // If we can't parse the error, return the end of file
    (lines.len().max(1), 1)
}

/// Perform additional linting checks
fn additional_checks(source: &str, errors: &mut Vec<LintError>) {
    // Check for common issues
    let lines: Vec<&str> = source.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        let line_no = line_num + 1;

        // Check for unbalanced parentheses
        if has_unbalanced_parens(line) {
            errors.push(LintError {
                line: line_no,
                column: find_unbalanced_paren_column(line),
                message: "Unbalanced parentheses".to_string(),
                severity: "warning".to_string(),
            });
        }

        // Check for unbalanced brackets
        if has_unbalanced_brackets(line) {
            errors.push(LintError {
                line: line_no,
                column: find_unbalanced_bracket_column(line),
                message: "Unbalanced brackets".to_string(),
                severity: "warning".to_string(),
            });
        }

        // Check for unbalanced braces
        if has_unbalanced_braces(line) {
            errors.push(LintError {
                line: line_no,
                column: find_unbalanced_brace_column(line),
                message: "Unbalanced braces".to_string(),
                severity: "warning".to_string(),
            });
        }

        // Check for trailing whitespace (info level)
        if line.ends_with(' ') || line.ends_with('\t') {
            errors.push(LintError {
                line: line_no,
                column: line.len(),
                message: "Trailing whitespace".to_string(),
                severity: "info".to_string(),
            });
        }
    }
}

/// Check for unbalanced parentheses (ignoring strings)
fn has_unbalanced_parens(line: &str) -> bool {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for c in line.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {}
            }
        }

        if count < 0 {
            return true; // More closing than opening
        }
    }

    count != 0
}

/// Check for unbalanced brackets
fn has_unbalanced_brackets(line: &str) -> bool {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for c in line.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '[' => count += 1,
                ']' => count -= 1,
                _ => {}
            }
        }

        if count < 0 {
            return true;
        }
    }

    count != 0
}

/// Check for unbalanced braces
fn has_unbalanced_braces(line: &str) -> bool {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for c in line.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '{' => count += 1,
                '}' => count -= 1,
                _ => {}
            }
        }

        if count < 0 {
            return true;
        }
    }

    count != 0
}

/// Find the column of the first unbalanced parenthesis
fn find_unbalanced_paren_column(line: &str) -> usize {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (col, c) in line.chars().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '(' => count += 1,
                ')' => {
                    count -= 1;
                    if count < 0 {
                        return col + 1;
                    }
                }
                _ => {}
            }
        }
    }

    line.len()
}

/// Find the column of the first unbalanced bracket
fn find_unbalanced_bracket_column(line: &str) -> usize {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (col, c) in line.chars().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '[' => count += 1,
                ']' => {
                    count -= 1;
                    if count < 0 {
                        return col + 1;
                    }
                }
                _ => {}
            }
        }
    }

    line.len()
}

/// Find the column of the first unbalanced brace
fn find_unbalanced_brace_column(line: &str) -> usize {
    let mut count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (col, c) in line.chars().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            continue;
        }

        if !in_string {
            match c {
                '{' => count += 1,
                '}' => {
                    count -= 1;
                    if count < 0 {
                        return col + 1;
                    }
                }
                _ => {}
            }
        }
    }

    line.len()
}
