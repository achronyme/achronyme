/// Formatting module for Achronyme source code
/// Adapted from achronyme-lsp formatting.rs

/// Context for tracking formatting state across lines
#[derive(Debug, Clone)]
struct FormatContext {
    indent_level: usize,
    indent_size: usize,
}

impl Default for FormatContext {
    fn default() -> Self {
        Self {
            indent_level: 0,
            indent_size: 4,
        }
    }
}

/// Format entire Achronyme source code
pub fn format_code(source: &str) -> String {
    let context = FormatContext::default();
    let mut formatted_lines = Vec::new();
    let mut context = context;

    for line in source.lines() {
        // Update context based on current line
        update_context_for_line(&mut context, line);

        let formatted = format_line(line, &context);
        formatted_lines.push(formatted);
    }

    // Join with newlines and ensure final newline
    let result = formatted_lines.join("\n");
    if source.ends_with('\n') && !result.ends_with('\n') {
        format!("{}\n", result)
    } else {
        result
    }
}

/// Update formatting context based on braces in line
fn update_context_for_line(context: &mut FormatContext, line: &str) {
    let trimmed = line.trim();

    // Decrease indent for lines starting with closing braces
    if (trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')'))
        && context.indent_level >= context.indent_size
    {
        context.indent_level -= context.indent_size;
    }

    // Count net brace changes for next line
    let (opens, closes) = count_braces_outside_strings(line);
    let net = opens as i32 - closes as i32;

    if net > 0 {
        context.indent_level += (net as usize) * context.indent_size;
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
fn format_line(line: &str, context: &FormatContext) -> String {
    // Preserve empty lines
    if line.trim().is_empty() {
        return String::new();
    }

    let trimmed = line.trim();

    // Preserve comment lines but fix indentation
    if trimmed.starts_with("//") {
        let indent = " ".repeat(context.indent_level);
        return format!("{}{}", indent, trimmed);
    }

    // Apply formatting rules
    let mut result = trimmed.to_string();

    // Normalize operators
    result = normalize_operators(&result);

    // Normalize commas
    result = normalize_commas(&result);

    // Normalize type annotations
    result = normalize_type_annotations(&result);

    // Normalize arrow functions
    result = normalize_arrow_functions(&result);

    // Normalize control flow
    result = normalize_control_flow(&result);

    // Normalize braces
    result = normalize_braces(&result);

    // Apply indentation
    let indent = context.indent_level;
    let indent_str = " ".repeat(indent);

    // Trim trailing whitespace
    let result = result.trim_end();

    format!("{}{}", indent_str, result)
}

/// Normalize spacing around binary operators
fn normalize_operators(line: &str) -> String {
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

        // Handle operators outside strings
        match c {
            // Range operators (no spaces)
            '.' if i + 1 < chars.len() && chars[i + 1] == '.' => {
                while result.ends_with(' ') {
                    result.pop();
                }
                result.push('.');
                result.push('.');
                i += 2;

                if i < chars.len() && chars[i] == '=' {
                    result.push('=');
                    i += 1;
                }

                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            // Arrow function (spaces around =>)
            '=' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                if !result.ends_with(' ') && !result.is_empty() {
                    result.push(' ');
                }
                result.push('=');
                result.push('>');
                i += 2;
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

            // Assignment operator
            '=' => {
                ensure_space_before(&mut result);
                result.push('=');
                i += 1;
                ensure_space_after(&mut result, &chars, &mut i);
            }

            // Binary arithmetic operators
            '+' | '*' | '/' | '%' | '^' => {
                let is_unary = result.is_empty()
                    || result.ends_with('(')
                    || result.ends_with('[')
                    || result.ends_with(',')
                    || result.ends_with('=')
                    || result.ends_with("return ")
                    || result.trim().is_empty();

                if is_unary && c == '+' {
                    result.push(c);
                    i += 1;
                } else {
                    ensure_space_before(&mut result);
                    result.push(c);
                    i += 1;
                    ensure_space_after(&mut result, &chars, &mut i);
                }
            }

            // Minus with special handling for unary minus
            '-' => {
                let is_unary = result.is_empty()
                    || result.ends_with('(')
                    || result.ends_with('[')
                    || result.ends_with(',')
                    || result.ends_with(' ')
                    || result.ends_with('=')
                    || result.ends_with("return ")
                    || result.trim().is_empty();

                if is_unary {
                    if i + 1 < chars.len() && (chars[i + 1].is_ascii_digit() || chars[i + 1] == '.')
                    {
                        result.push('-');
                        i += 1;
                    } else if i + 1 < chars.len() && chars[i + 1].is_alphanumeric() {
                        result.push('-');
                        i += 1;
                    } else {
                        ensure_space_before(&mut result);
                        result.push('-');
                        i += 1;
                        ensure_space_after(&mut result, &chars, &mut i);
                    }
                } else {
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
            }

            _ => {
                result.push(c);
                i += 1;
            }
        }
    }

    result
}

/// Ensure space before current position in result
fn ensure_space_before(result: &mut String) {
    while result.ends_with(' ') {
        result.pop();
    }
    if !result.is_empty() {
        result.push(' ');
    }
}

/// Ensure space after, consuming spaces in input
fn ensure_space_after(result: &mut String, chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i] == ' ' {
        *i += 1;
    }
    if *i < chars.len() {
        result.push(' ');
    }
}

/// Normalize spacing around commas
fn normalize_commas(line: &str) -> String {
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
            while result.ends_with(' ') {
                result.pop();
            }
            result.push(',');
            i += 1;

            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }

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
fn normalize_type_annotations(line: &str) -> String {
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

        if c == ':' {
            result.push(':');
            i += 1;

            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }

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

/// Normalize arrow functions
fn normalize_arrow_functions(line: &str) -> String {
    // Already handled in normalize_operators
    line.to_string()
}

/// Normalize control flow keywords
fn normalize_control_flow(line: &str) -> String {
    let mut result = line.to_string();

    let keywords = ["if", "while", "for", "match", "catch"];

    for keyword in &keywords {
        let pattern = format!("{}(", keyword);
        let replacement = format!("{} (", keyword);
        result = result.replace(&pattern, &replacement);
    }

    result = result.replace("else{", "else {");
    result = result.replace("else  {", "else {");
    result = result.replace("}else", "} else");

    result
}

/// Normalize brace spacing
fn normalize_braces(line: &str) -> String {
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
                if result.ends_with(')') {
                    result.push(' ');
                }
                result.push('{');
                i += 1;

                if i < chars.len() && chars[i] == '}' {
                    result.push(' ');
                    result.push('}');
                    i += 1;
                } else if i < chars.len() && chars[i] != ' ' {
                    result.push(' ');
                }
            }

            '}' => {
                if !result.ends_with(' ') && !result.ends_with('{') && !result.is_empty() {
                    result.push(' ');
                }
                result.push('}');
                i += 1;
            }

            '[' => {
                result.push('[');
                i += 1;
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            ']' => {
                while result.ends_with(' ') {
                    result.pop();
                }
                result.push(']');
                i += 1;
            }

            '(' => {
                result.push('(');
                i += 1;
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }

            ')' => {
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
