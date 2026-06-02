use crate::lexer::Lexer;

// ── Error on invalid <-- partial ─────────────────────────────────

#[test]
fn partial_signal_assign_error() {
    // `<-` without the third `-` is an error
    let err = Lexer::tokenize("a <- b").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E302"));
}

// ── Malformed input error codes ──────────────────────────────────

#[test]
fn unexpected_character_error() {
    let err = Lexer::tokenize("signal input #x;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E302"));
    assert!(err.message.contains("unexpected character"));
}

#[test]
fn unterminated_string_at_eof() {
    let err = Lexer::tokenize(r#"include "path/to/file"#).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}

#[test]
fn unterminated_block_comment_multiline() {
    let err = Lexer::tokenize("/* starts here\nbut never\nends").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}

#[test]
fn invalid_escape_backslash_b() {
    let err = Lexer::tokenize(r#""\b""#).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E303"));
    assert!(err.message.contains("\\b"));
}

#[test]
fn hex_prefix_only() {
    let err = Lexer::tokenize("var x = 0x;").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E302"));
    assert!(err.message.contains("hex digits"));
}

#[test]
fn string_with_escape_at_eof() {
    let err = Lexer::tokenize(r#""hello\"#).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}
