/// Process escape sequences in a raw string literal value.
///
/// The lexer stores string contents with escapes unprocessed (e.g., `\n` as
/// literal backslash + `n`). Call this function to convert them to their
/// interpreted values (e.g., real newline character).
pub fn unescape(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\u{08}'),
                Some('f') => result.push('\u{0C}'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}
