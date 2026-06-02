use super::*;

fn kinds(src: &str) -> Vec<TokenKind> {
    Lexer::tokenize(src)
        .unwrap()
        .into_iter()
        .map(|t| t.kind)
        .collect()
}

#[test]
fn simple_tokens() {
    assert_eq!(
        kinds("+ - * / %"),
        vec![
            TokenKind::Plus,
            TokenKind::Minus,
            TokenKind::Star,
            TokenKind::Slash,
            TokenKind::Percent,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn multi_char_ops() {
    assert_eq!(
        kinds("== != <= >= && || .."),
        vec![
            TokenKind::Eq,
            TokenKind::Neq,
            TokenKind::Le,
            TokenKind::Ge,
            TokenKind::And,
            TokenKind::Or,
            TokenKind::DotDot,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn keywords() {
    assert_eq!(
        kinds("let mut if else fn return"),
        vec![
            TokenKind::Let,
            TokenKind::Mut,
            TokenKind::If,
            TokenKind::Else,
            TokenKind::Fn,
            TokenKind::Return,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn ident_not_keyword() {
    let tokens = Lexer::tokenize("letter").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::Ident);
    assert_eq!(tokens[0].lexeme, "letter");
}

#[test]
fn number_literal() {
    let tokens = Lexer::tokenize("42").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::Integer);
    assert_eq!(tokens[0].lexeme, "42");
}

#[test]
fn string_escapes() {
    let tokens = Lexer::tokenize(r#""hello\nworld""#).unwrap();
    assert_eq!(tokens[0].kind, TokenKind::StringLit);
    // P-01 fix: lexer stores raw escape sequences, not processed values
    assert_eq!(tokens[0].lexeme, r"hello\nworld");
    assert_eq!(tokens[0].lexeme.len(), 12); // literal backslash + n, not newline

    // Verify all escape types are stored raw
    let tokens = Lexer::tokenize(r#""a\tb\nc\\d\"e""#).unwrap();
    assert_eq!(tokens[0].lexeme, r#"a\tb\nc\\d\"e"#);
}

#[test]
fn unterminated_string() {
    assert!(Lexer::tokenize(r#""unterminated"#).is_err());
}

#[test]
fn line_comment() {
    assert_eq!(
        kinds("1 // comment\n2"),
        vec![TokenKind::Integer, TokenKind::Integer, TokenKind::Eof]
    );
}

#[test]
fn block_comment() {
    assert_eq!(
        kinds("1 /* comment */ 2"),
        vec![TokenKind::Integer, TokenKind::Integer, TokenKind::Eof]
    );
}

#[test]
fn delimiters() {
    assert_eq!(
        kinds("()[]{},:;"),
        vec![
            TokenKind::LParen,
            TokenKind::RParen,
            TokenKind::LBracket,
            TokenKind::RBracket,
            TokenKind::LBrace,
            TokenKind::RBrace,
            TokenKind::Comma,
            TokenKind::Colon,
            TokenKind::Semicolon,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn string_utf8_multibyte() {
    // P-05 fix: multi-byte UTF-8 characters in strings
    let tokens = Lexer::tokenize("\"café\"").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::StringLit);
    assert_eq!(tokens[0].lexeme, "café");

    let tokens = Lexer::tokenize("\"hello 世界\"").unwrap();
    assert_eq!(tokens[0].lexeme, "hello 世界");

    // Emoji (4-byte UTF-8)
    let tokens = Lexer::tokenize("\"🎉\"").unwrap();
    assert_eq!(tokens[0].lexeme, "🎉");
}

#[test]
fn string_utf8_column_tracking() {
    // After a string with multi-byte chars, the next token's column must be correct.
    // "café" = 6 chars (c,a,f,é,") + opening quote = columns 1..7, next token at col 9
    let tokens = Lexer::tokenize("\"café\" x").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::StringLit);
    // String span: col 1 (opening ") to col 7 (after closing ")
    assert_eq!(tokens[0].span.col_start, 1);
    assert_eq!(tokens[0].span.col_end, 7);
    // "x" should be at col 8 (space at col 7, x at col 8)
    assert_eq!(tokens[1].kind, TokenKind::Ident);
    assert_eq!(tokens[1].span.col_start, 8);

    // 3-byte UTF-8: "世" (3 bytes) — string "世" is 3 columns: " 世 "
    let tokens = Lexer::tokenize("\"世\" y").unwrap();
    assert_eq!(tokens[0].span.col_start, 1);
    assert_eq!(tokens[0].span.col_end, 4); // " at 1, 世 at 2, " at 3, end at 4
    assert_eq!(tokens[1].span.col_start, 5);

    // 4-byte UTF-8: emoji
    let tokens = Lexer::tokenize("\"🎉\" z").unwrap();
    assert_eq!(tokens[0].span.col_start, 1);
    assert_eq!(tokens[0].span.col_end, 4);
    assert_eq!(tokens[1].span.col_start, 5);
}

#[test]
fn unescape_basic() {
    assert_eq!(unescape(r"hello\nworld"), "hello\nworld");
    assert_eq!(unescape(r"tab\there"), "tab\there");
    assert_eq!(unescape(r"back\\slash"), "back\\slash");
    assert_eq!(unescape(r#"say\"hi\""#), "say\"hi\"");
    assert_eq!(unescape(r"\b\f\r"), "\u{08}\u{0C}\r");
    assert_eq!(unescape("no escapes"), "no escapes");
    assert_eq!(unescape(""), "");
}

#[test]
fn token_span_has_byte_range() {
    let tokens = Lexer::tokenize("let x = 42").unwrap();
    // "let" is at bytes 0..3
    assert_eq!(tokens[0].span.byte_start, 0);
    assert_eq!(tokens[0].span.byte_end, 3);
    assert_eq!(tokens[0].span.line_start, 1);
    assert_eq!(tokens[0].span.col_start, 1);
    assert_eq!(tokens[0].span.line_end, 1);
    assert_eq!(tokens[0].span.col_end, 4);
    // "x" is at bytes 4..5
    assert_eq!(tokens[1].span.byte_start, 4);
    assert_eq!(tokens[1].span.byte_end, 5);
    // "=" is at bytes 6..7
    assert_eq!(tokens[2].span.byte_start, 6);
    assert_eq!(tokens[2].span.byte_end, 7);
    // "42" is at bytes 8..10
    assert_eq!(tokens[3].span.byte_start, 8);
    assert_eq!(tokens[3].span.byte_end, 10);
}

#[test]
fn token_span_multiline() {
    let tokens = Lexer::tokenize("a\nb").unwrap();
    // "a" on line 1
    assert_eq!(tokens[0].span.line_start, 1);
    assert_eq!(tokens[0].span.line_end, 1);
    // "b" on line 2
    assert_eq!(tokens[1].span.line_start, 2);
    assert_eq!(tokens[1].span.line_end, 2);
}
