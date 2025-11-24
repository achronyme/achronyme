use crate::parser::AstParser;

impl AstParser {
    /// Process escape sequences in string literals
    pub(super) fn process_escape_sequences(&mut self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next_ch) = chars.next() {
                    match next_ch {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        'r' => result.push('\r'),
                        '\\' => result.push('\\'),
                        '"' => result.push('"'),
                        _ => {
                            // Unknown escape sequence, keep as is
                            result.push('\\');
                            result.push(next_ch);
                        }
                    }
                } else {
                    result.push('\\');
                }
            } else {
                result.push(ch);
            }
        }

        result
    }
}
