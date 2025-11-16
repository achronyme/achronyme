use achronyme_parser::ast::AstNode;
use achronyme_parser::parse;

/// Represents an open document in the LSP server
pub struct Document {
    /// The current text content of the document
    text: String,
    /// Lines of the document (cached for position calculations)
    lines: Vec<String>,
    /// Parsed AST (if parsing succeeded)
    ast: Option<Vec<AstNode>>,
    /// Parse error (if parsing failed)
    parse_error: Option<String>,
}

impl Document {
    pub fn new(text: String) -> Self {
        let lines = text.lines().map(|s| s.to_string()).collect();
        let (ast, parse_error) = match parse(&text) {
            Ok(nodes) => (Some(nodes), None),
            Err(e) => (None, Some(e)),
        };

        Self {
            text,
            lines,
            ast,
            parse_error,
        }
    }

    pub fn update_text(&mut self, new_text: String) {
        self.lines = new_text.lines().map(|s| s.to_string()).collect();
        let (ast, parse_error) = match parse(&new_text) {
            Ok(nodes) => (Some(nodes), None),
            Err(e) => (None, Some(e)),
        };

        self.text = new_text;
        self.ast = ast;
        self.parse_error = parse_error;
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn ast(&self) -> Option<&Vec<AstNode>> {
        self.ast.as_ref()
    }

    pub fn parse_error(&self) -> Option<&str> {
        self.parse_error.as_deref()
    }

    /// Get the word at a given position (line, column)
    pub fn word_at_position(&self, line: u32, character: u32) -> Option<String> {
        let line_idx = line as usize;
        if line_idx >= self.lines.len() {
            return None;
        }

        let line_text = &self.lines[line_idx];
        let char_idx = character as usize;

        if char_idx >= line_text.len() {
            return None;
        }

        // Find word boundaries
        let chars: Vec<char> = line_text.chars().collect();

        // Find start of word
        let mut start = char_idx;
        while start > 0 && is_word_char(chars[start - 1]) {
            start -= 1;
        }

        // Find end of word
        let mut end = char_idx;
        while end < chars.len() && is_word_char(chars[end]) {
            end += 1;
        }

        if start < end {
            Some(chars[start..end].iter().collect())
        } else {
            None
        }
    }

    /// Get byte offset from position
    #[allow(dead_code)]
    pub fn offset_from_position(&self, line: u32, character: u32) -> usize {
        let mut offset = 0;
        for (idx, l) in self.lines.iter().enumerate() {
            if idx == line as usize {
                offset += character as usize;
                break;
            }
            offset += l.len() + 1; // +1 for newline
        }
        offset
    }

    /// Get position from byte offset
    #[allow(dead_code)]
    pub fn position_from_offset(&self, offset: usize) -> (u32, u32) {
        let mut current_offset = 0;
        for (idx, l) in self.lines.iter().enumerate() {
            let line_end = current_offset + l.len() + 1; // +1 for newline
            if offset < line_end {
                return (idx as u32, (offset - current_offset) as u32);
            }
            current_offset = line_end;
        }
        // If offset is beyond the document, return end of last line
        let last_line = self.lines.len().saturating_sub(1);
        let last_char = self.lines.get(last_line).map(|l| l.len()).unwrap_or(0);
        (last_line as u32, last_char as u32)
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
