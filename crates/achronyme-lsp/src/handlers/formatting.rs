use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Context for tracking formatting state across lines
#[derive(Debug, Clone)]
pub struct FormatContext {
    /// Current indentation level (number of spaces)
    indent_level: usize,
    /// Number of spaces per indent level
    indent_size: usize,
    /// Stack of open brackets/braces for tracking nesting
    brace_stack: Vec<char>,
}

impl Default for FormatContext {
    fn default() -> Self {
        Self {
            indent_level: 0,
            indent_size: 4,
            brace_stack: Vec::new(),
        }
    }
}

impl FormatContext {
    pub fn new(indent_size: usize) -> Self {
        Self {
            indent_level: 0,
            indent_size,
            brace_stack: Vec::new(),
        }
    }
}

/// Format an entire document and return the text edits needed
pub fn format_document(doc: &Document, options: &FormattingOptions) -> Vec<TextEdit> {
    let text = doc.text();
    let indent_size = options.tab_size as usize;
    let mut context = FormatContext::new(indent_size);
    let mut edits = Vec::new();

    let lines: Vec<&str> = text.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        // Update context based on previous line's braces
        update_context_for_line(&mut context, line);

        let formatted = format_line(line, &context);

        if formatted != *line {
            edits.push(TextEdit {
                range: Range {
                    start: Position {
                        line: line_num as u32,
                        character: 0,
                    },
                    end: Position {
                        line: line_num as u32,
                        character: line.len() as u32,
                    },
                },
                new_text: formatted,
            });
        }
    }

    edits
}

/// Update the formatting context based on braces in the line
fn update_context_for_line(context: &mut FormatContext, line: &str) {
    let trimmed = line.trim();

    // Decrease indent for lines starting with closing braces
    if trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')') {
        if context.indent_level >= context.indent_size {
            context.indent_level -= context.indent_size;
        }
        if !context.brace_stack.is_empty() {
            context.brace_stack.pop();
        }
    }

    // Count net brace changes for next line
    let (opens, closes) = count_braces_outside_strings(line);
    let net = opens as i32 - closes as i32;

    if net > 0 {
        for _ in 0..net {
            context.indent_level += context.indent_size;
            context.brace_stack.push('{');
        }
    }
}

/// Count opening and closing braces outside of string literals
fn count_braces_outside_strings(line: &str) -> (usize, usize) {
    let mut opens = 0;
    let mut closes = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let chars: Vec<char> = line.chars().collect();

    for i in 0..chars.len() {
        let c = chars[i];

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
                '{' | '[' | '(' => opens += 1,
                '}' | ']' | ')' => closes += 1,
                _ => {}
            }
        }
    }

    (opens, closes)
}

/// Format a single line of code
pub fn format_line(line: &str, context: &FormatContext) -> String {
    // Preserve empty lines
    if line.trim().is_empty() {
        return String::new();
    }

    // Get the trimmed content first
    let trimmed = line.trim();

    // Check for comment lines (preserve as-is but fix indentation)
    if trimmed.starts_with("//") {
        let indent = " ".repeat(context.indent_level);
        return format!("{}{}", indent, trimmed);
    }

    // Apply formatting rules
    let mut result = trimmed.to_string();

    // Normalize operators (spaces around binary operators)
    result = normalize_operators(&result);

    // Normalize commas (space after comma)
    result = normalize_commas(&result);

    // Normalize type annotations (space after colon in type context)
    result = normalize_type_annotations(&result);

    // Normalize arrow functions
    result = normalize_arrow_functions(&result);

    // Normalize control flow keywords
    result = normalize_control_flow(&result);

    // Normalize braces
    result = normalize_braces(&result);

    // Apply indentation
    let indent = calculate_indent(trimmed, context);
    let indent_str = " ".repeat(indent);

    // Remove trailing whitespace (should be handled by trimming, but be safe)
    let result = result.trim_end();

    format!("{}{}", indent_str, result)
}

/// Calculate the proper indentation for a line
fn calculate_indent(trimmed_line: &str, context: &FormatContext) -> usize {
    // Lines starting with closing braces should use decreased indent
    if trimmed_line.starts_with('}')
        || trimmed_line.starts_with(']')
        || trimmed_line.starts_with(')')
    {
        // The context has already been adjusted in update_context_for_line
        context.indent_level
    } else {
        context.indent_level
    }
}

/// Normalize spacing around binary operators
pub fn normalize_operators(line: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    // Track string context
    let mut in_string = false;
    let mut escape_next = false;

    while i < chars.len() {
        let c = chars[i];

        if escape_next {
            escape_next = false;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            result.push(c);
            i += 1;
            continue;
        }

        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        // Handle operators outside strings
        match c {
            // Range operators (no spaces)
            '.' if i + 1 < chars.len() && chars[i + 1] == '.' => {
                // Remove spaces before ..
                while result.ends_with(' ') {
                    result.pop();
                }
                result.push('.');
                result.push('.');
                i += 2;

                // Handle ..= (inclusive range)
                if i < chars.len() && chars[i] == '=' {
                    result.push('=');
                    i += 1;
                }

                // Remove spaces after ..
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            // Arrow function (spaces around =>)
            '=' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                // Ensure space before =>
                if !result.ends_with(' ') && !result.is_empty() {
                    result.push(' ');
                }
                result.push('=');
                result.push('>');
                i += 2;
                // Ensure space after =>
                if i < chars.len() && chars[i] != ' ' {
                    result.push(' ');
                }
            }

            // Comparison operators
            '=' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                ensure_space_before(&mut result);
                result.push('=');
                result.push('=');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            '!' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                ensure_space_before(&mut result);
                result.push('!');
                result.push('=');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            '<' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                ensure_space_before(&mut result);
                result.push('<');
                result.push('=');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            '>' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                ensure_space_before(&mut result);
                result.push('>');
                result.push('=');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            // Logical operators
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                ensure_space_before(&mut result);
                result.push('&');
                result.push('&');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                ensure_space_before(&mut result);
                result.push('|');
                result.push('|');
                i += 2;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            // Single character comparison operators
            '<' | '>' => {
                ensure_space_before(&mut result);
                result.push(c);
                i += 1;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            // Assignment operator (but not in == or !=)
            '=' => {
                ensure_space_before(&mut result);
                result.push('=');
                i += 1;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            // Binary arithmetic operators
            '+' | '*' | '/' | '%' | '^' => {
                // Check if this could be unary (at start or after operator/open paren)
                let is_unary = result.is_empty()
                    || result.ends_with('(')
                    || result.ends_with('[')
                    || result.ends_with(',')
                    || result.ends_with('=')
                    || result.ends_with("return ")
                    || result.trim().is_empty();

                if is_unary && c == '+' {
                    // Unary plus - don't add space
                    result.push(c);
                    i += 1;
                } else {
                    ensure_space_before(&mut result);
                    result.push(c);
                    i += 1;
                    ensure_space_after(&mut result, &chars, &mut i);
                }
            }

            // Minus needs special handling for unary minus
            '-' => {
                // Check if this is likely unary minus
                let is_unary = result.is_empty()
                    || result.ends_with('(')
                    || result.ends_with('[')
                    || result.ends_with(',')
                    || result.ends_with(' ')
                    || result.ends_with('=')
                    || result.ends_with("return ")
                    || result.trim().is_empty();

                if is_unary {
                    // Check if there's a number after (unary minus)
                    if i + 1 < chars.len()
                        && (chars[i + 1].is_ascii_digit() || chars[i + 1] == '.')
                    {
                        // Unary minus with number - no space after
                        result.push('-');
                        i += 1;
                    } else if i + 1 < chars.len() && chars[i + 1].is_alphanumeric() {
                        // Unary minus with variable - no space after
                        result.push('-');
                        i += 1;
                    } else {
                        // Binary minus
                        ensure_space_before(&mut result);
                        result.push('-');
                        i += 1;
                        ensure_space_after(&mut result, &chars, &mut i);
                    }
                } else {
                    // Binary minus
                    ensure_space_before(&mut result);
                    result.push('-');
                    i += 1;
                    ensure_space_after(&mut result, &chars, &mut i);
                }
            }

            // Unary NOT
            '!' if !(i + 1 < chars.len() && chars[i + 1] == '=') => {
                result.push('!');
                i += 1;
                // No space after unary !
            }

            _ => {
                result.push(c);
                i += 1;
            }
        }
    }

    result
}

/// Ensure there is a space before the current position in result
fn ensure_space_before(result: &mut String) {
    // Remove any existing spaces
    while result.ends_with(' ') {
        result.pop();
    }
    // Add exactly one space if result is not empty
    if !result.is_empty() {
        result.push(' ');
    }
}

/// Ensure there is a space after, consuming any existing spaces in input
fn ensure_space_after(result: &mut String, chars: &[char], i: &mut usize) {
    // Skip any existing spaces in input
    while *i < chars.len() && chars[*i] == ' ' {
        *i += 1;
    }
    // Add exactly one space
    if *i < chars.len() {
        result.push(' ');
    }
}

/// Normalize spacing around commas (space after, no space before)
pub fn normalize_commas(line: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    let mut in_string = false;
    let mut escape_next = false;

    while i < chars.len() {
        let c = chars[i];

        if escape_next {
            escape_next = false;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            result.push(c);
            i += 1;
            continue;
        }

        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        if c == ',' {
            // Remove space before comma
            while result.ends_with(' ') {
                result.pop();
            }
            result.push(',');
            i += 1;

            // Skip any spaces after comma
            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }

            // Add exactly one space after comma (if not at end of line)
            if i < chars.len() {
                result.push(' ');
            }
        } else {
            result.push(c);
            i += 1;
        }
    }

    result
}

/// Normalize type annotations (space after colon)
pub fn normalize_type_annotations(line: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    let mut in_string = false;
    let mut escape_next = false;

    while i < chars.len() {
        let c = chars[i];

        if escape_next {
            escape_next = false;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            result.push(c);
            i += 1;
            continue;
        }

        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        // Handle colon in type annotation context
        // Type annotations are like `name: Type` but not in records `{key: value}`
        if c == ':' {
            result.push(':');
            i += 1;

            // Skip any existing spaces
            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }

            // Add exactly one space after colon
            if i < chars.len() {
                result.push(' ');
            }
        } else {
            result.push(c);
            i += 1;
        }
    }

    result
}

/// Normalize arrow functions (spaces around =>)
pub fn normalize_arrow_functions(line: &str) -> String {
    // Already handled in normalize_operators
    line.to_string()
}

/// Normalize control flow keywords (space before opening paren, space before brace)
pub fn normalize_control_flow(line: &str) -> String {
    let mut result = line.to_string();

    // Keywords that should have space before (
    let keywords = ["if", "while", "for", "match", "catch"];

    for keyword in &keywords {
        let pattern = format!("{}(", keyword);
        let replacement = format!("{} (", keyword);
        result = result.replace(&pattern, &replacement);
    }

    // Normalize else { and else if (
    result = result.replace("else{", "else {");
    result = result.replace("else  {", "else {");
    result = result.replace("}else", "} else");

    result
}

/// Normalize brace spacing
pub fn normalize_braces(line: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    let mut in_string = false;
    let mut escape_next = false;

    while i < chars.len() {
        let c = chars[i];

        if escape_next {
            escape_next = false;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '\\' && in_string {
            escape_next = true;
            result.push(c);
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            result.push(c);
            i += 1;
            continue;
        }

        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        match c {
            '{' => {
                // Space before { if preceded by )
                if result.ends_with(')') {
                    result.push(' ');
                }
                result.push('{');
                i += 1;

                // Handle empty blocks: { }
                if i < chars.len() && chars[i] == '}' {
                    result.push(' ');
                    result.push('}');
                    i += 1;
                } else if i < chars.len() && chars[i] != ' ' {
                    // Space after { if not followed by space or newline
                    result.push(' ');
                }
            }

            '}' => {
                // Space before } if not preceded by space or {
                if !result.ends_with(' ') && !result.ends_with('{') && !result.is_empty() {
                    result.push(' ');
                }
                result.push('}');
                i += 1;
            }

            '[' => {
                result.push('[');
                i += 1;
                // Skip spaces after [
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            ']' => {
                // Remove spaces before ]
                while result.ends_with(' ') {
                    result.pop();
                }
                result.push(']');
                i += 1;
            }

            '(' => {
                result.push('(');
                i += 1;
                // Skip spaces after (
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            ')' => {
                // Remove spaces before )
                while result.ends_with(' ') {
                    result.pop();
                }
                result.push(')');
                i += 1;
            }

            _ => {
                result.push(c);
                i += 1;
            }
        }
    }

    result
}

/// Format a record literal for better readability
pub fn format_record_literal(text: &str) -> String {
    // Simple implementation - just ensure spacing
    let text = text.trim();
    if !text.starts_with('{') || !text.ends_with('}') {
        return text.to_string();
    }

    let inner = &text[1..text.len() - 1].trim();
    if inner.is_empty() {
        return "{ }".to_string();
    }

    format!("{{ {} }}", inner)
}

/// Format a vector/array literal for better readability
pub fn format_vector_literal(text: &str) -> String {
    // Simple implementation - just ensure spacing
    let text = text.trim();
    if !text.starts_with('[') || !text.ends_with(']') {
        return text.to_string();
    }

    let inner = &text[1..text.len() - 1].trim();
    if inner.is_empty() {
        return "[]".to_string();
    }

    format!("[{}]", inner)
}

/// Trim trailing whitespace from a line
pub fn trim_trailing_whitespace(line: &str) -> String {
    line.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_operators_arithmetic() {
        assert_eq!(normalize_operators("let x=5+3*2"), "let x = 5 + 3 * 2");
        assert_eq!(normalize_operators("a+b-c"), "a + b - c");
        assert_eq!(normalize_operators("x*y/z"), "x * y / z");
        assert_eq!(normalize_operators("a^2"), "a ^ 2");
    }

    #[test]
    fn test_normalize_operators_comparison() {
        assert_eq!(normalize_operators("x==y"), "x == y");
        assert_eq!(normalize_operators("a>=b"), "a >= b");
        assert_eq!(normalize_operators("c<=d"), "c <= d");
        assert_eq!(normalize_operators("e!=f"), "e != f");
        assert_eq!(normalize_operators("g>h"), "g > h");
        assert_eq!(normalize_operators("i<j"), "i < j");
    }

    #[test]
    fn test_normalize_operators_logical() {
        assert_eq!(normalize_operators("a&&b"), "a && b");
        assert_eq!(normalize_operators("c||d"), "c || d");
    }

    #[test]
    fn test_normalize_operators_range() {
        // Range operators should have NO spaces
        assert_eq!(normalize_operators("1..5"), "1..5");
        assert_eq!(normalize_operators("1 .. 5"), "1..5");
        assert_eq!(normalize_operators("1..=10"), "1..=10");
        assert_eq!(normalize_operators("a .. b"), "a..b");
    }

    #[test]
    fn test_normalize_operators_arrow() {
        assert_eq!(normalize_operators("x=>x^2"), "x => x ^ 2");
        // Note: commas are handled by normalize_commas, not normalize_operators
        assert_eq!(normalize_operators("(x,y)=>x+y"), "(x,y) => x + y");
    }

    #[test]
    fn test_normalize_operators_unary() {
        // Unary operators should not have space after
        assert_eq!(normalize_operators("!x"), "!x");
        // Note: "! x" has a space that gets preserved, but it's not typical input
        // The unary ! without space works correctly
    }

    #[test]
    fn test_normalize_operators_negative_numbers() {
        // Negative numbers at start
        assert_eq!(normalize_operators("-5"), "-5");
        assert_eq!(normalize_operators("let x = -5"), "let x = -5");
        // In expressions
        assert_eq!(normalize_operators("return -x"), "return -x");
    }

    #[test]
    fn test_normalize_operators_preserves_strings() {
        assert_eq!(
            normalize_operators(r#"let s = "a+b""#),
            r#"let s = "a+b""#
        );
        assert_eq!(
            normalize_operators(r#"let s = "x==y""#),
            r#"let s = "x==y""#
        );
    }

    #[test]
    fn test_normalize_commas() {
        assert_eq!(normalize_commas("[1,2,3,4,5]"), "[1, 2, 3, 4, 5]");
        // Note: colons in records are handled by normalize_type_annotations
        assert_eq!(normalize_commas("{a:1,b:2}"), "{a:1, b:2}");
        assert_eq!(normalize_commas("f(a,b,c)"), "f(a, b, c)");
    }

    #[test]
    fn test_normalize_commas_preserves_strings() {
        assert_eq!(
            normalize_commas(r#"let s = "a,b,c""#),
            r#"let s = "a,b,c""#
        );
    }

    #[test]
    fn test_normalize_type_annotations() {
        assert_eq!(normalize_type_annotations("x:Number"), "x: Number");
        assert_eq!(normalize_type_annotations("let x:Number = 5"), "let x: Number = 5");
    }

    #[test]
    fn test_normalize_control_flow() {
        assert_eq!(normalize_control_flow("if(x > 0)"), "if (x > 0)");
        assert_eq!(normalize_control_flow("while(true)"), "while (true)");
        assert_eq!(normalize_control_flow("for(i in items)"), "for (i in items)");
    }

    #[test]
    fn test_normalize_braces() {
        assert_eq!(normalize_braces("{}"), "{ }");
        assert_eq!(normalize_braces("{x}"), "{ x }");
        assert_eq!(normalize_braces("( x )"), "(x)");
        assert_eq!(normalize_braces("[ x ]"), "[x]");
    }

    #[test]
    fn test_format_line_basic() {
        let context = FormatContext::default();
        assert_eq!(format_line("let x=5+3*2", &context), "let x = 5 + 3 * 2");
    }

    #[test]
    fn test_format_line_with_indentation() {
        let mut context = FormatContext::default();
        context.indent_level = 4;
        let result = format_line("return x", &context);
        assert_eq!(result, "    return x");
    }

    #[test]
    fn test_format_line_preserves_comments() {
        let context = FormatContext::default();
        let result = format_line("// This is a comment", &context);
        assert_eq!(result, "// This is a comment");
    }

    #[test]
    fn test_format_line_empty_line() {
        let context = FormatContext::default();
        assert_eq!(format_line("", &context), "");
        assert_eq!(format_line("   ", &context), "");
    }

    #[test]
    fn test_trim_trailing_whitespace() {
        assert_eq!(trim_trailing_whitespace("hello   "), "hello");
        assert_eq!(trim_trailing_whitespace("world\t\t"), "world");
    }

    #[test]
    fn test_format_record_literal() {
        assert_eq!(format_record_literal("{}"), "{ }");
        assert_eq!(format_record_literal("{ a: 1 }"), "{ a: 1 }");
    }

    #[test]
    fn test_format_vector_literal() {
        assert_eq!(format_vector_literal("[]"), "[]");
        assert_eq!(format_vector_literal("[1, 2, 3]"), "[1, 2, 3]");
    }

    #[test]
    fn test_count_braces_outside_strings() {
        assert_eq!(count_braces_outside_strings("{"), (1, 0));
        assert_eq!(count_braces_outside_strings("}"), (0, 1));
        assert_eq!(count_braces_outside_strings("{}"), (1, 1));
        assert_eq!(count_braces_outside_strings(r#""{""#), (0, 0));
    }

    #[test]
    fn test_complex_formatting() {
        let context = FormatContext::default();

        // Test full line formatting
        let input = "let arr=[1,2,3,4,5]";
        let expected = "let arr = [1, 2, 3, 4, 5]";
        assert_eq!(format_line(input, &context), expected);

        let input = "let f=x=>x^2";
        let expected = "let f = x => x ^ 2";
        assert_eq!(format_line(input, &context), expected);

        let input = r#"let person={name:"Alice",age:30}"#;
        let expected = r#"let person = { name: "Alice", age: 30 }"#;
        assert_eq!(format_line(input, &context), expected);
    }

    #[test]
    fn test_if_else_formatting() {
        let context = FormatContext::default();
        let input = "if(x>0){return x}else{return -x}";
        let expected = "if (x > 0) { return x } else { return -x }";
        assert_eq!(format_line(input, &context), expected);
    }
}
