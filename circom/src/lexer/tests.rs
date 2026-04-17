//! Lexer tokenization tests.

use super::*;

fn kinds(src: &str) -> Vec<TokenKind> {
    Lexer::tokenize(src)
        .unwrap()
        .into_iter()
        .map(|t| t.kind)
        .collect()
}

#[allow(dead_code)]
fn lexemes(src: &str) -> Vec<String> {
    Lexer::tokenize(src)
        .unwrap()
        .into_iter()
        .map(|t| t.lexeme)
        .collect()
}

// ── Signal operators ─────────────────────────────────────────────

#[test]
fn signal_constraint_assign() {
    assert_eq!(
        kinds("a <== b"),
        vec![
            TokenKind::Ident,
            TokenKind::ConstraintAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

#[test]
fn signal_assign() {
    assert_eq!(
        kinds("a <-- b"),
        vec![
            TokenKind::Ident,
            TokenKind::SignalAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

#[test]
fn constraint_eq() {
    assert_eq!(
        kinds("a === b"),
        vec![
            TokenKind::Ident,
            TokenKind::ConstraintEq,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

#[test]
fn reverse_constraint_assign() {
    assert_eq!(
        kinds("a ==> b"),
        vec![
            TokenKind::Ident,
            TokenKind::RConstraintAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

#[test]
fn reverse_signal_assign() {
    assert_eq!(
        kinds("a --> b"),
        vec![
            TokenKind::Ident,
            TokenKind::RSignalAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

// ── Disambiguation ───────────────────────────────────────────────

#[test]
fn less_than_vs_constraint_assign() {
    // `<` then `<==` on separate expressions
    assert_eq!(
        kinds("a < b"),
        vec![
            TokenKind::Ident,
            TokenKind::Lt,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
    assert_eq!(
        kinds("a <= b"),
        vec![
            TokenKind::Ident,
            TokenKind::Le,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
    assert_eq!(
        kinds("a <== b"),
        vec![
            TokenKind::Ident,
            TokenKind::ConstraintAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}

#[test]
fn equals_disambiguation() {
    assert_eq!(kinds("=")[..2], [TokenKind::Assign, TokenKind::Eof]);
    assert_eq!(kinds("==")[..2], [TokenKind::Eq, TokenKind::Eof]);
    assert_eq!(kinds("===")[..2], [TokenKind::ConstraintEq, TokenKind::Eof]);
    assert_eq!(
        kinds("==>")[..2],
        [TokenKind::RConstraintAssign, TokenKind::Eof]
    );
}

#[test]
fn minus_disambiguation() {
    assert_eq!(kinds("-")[..2], [TokenKind::Minus, TokenKind::Eof]);
    assert_eq!(kinds("--")[..2], [TokenKind::Decrement, TokenKind::Eof]);
    assert_eq!(
        kinds("-->")[..2],
        [TokenKind::RSignalAssign, TokenKind::Eof]
    );
    assert_eq!(kinds("-=")[..2], [TokenKind::MinusAssign, TokenKind::Eof]);
}

#[test]
fn star_disambiguation() {
    assert_eq!(kinds("*")[..2], [TokenKind::Star, TokenKind::Eof]);
    assert_eq!(kinds("**")[..2], [TokenKind::Power, TokenKind::Eof]);
    assert_eq!(kinds("**=")[..2], [TokenKind::PowerAssign, TokenKind::Eof]);
    assert_eq!(kinds("*=")[..2], [TokenKind::StarAssign, TokenKind::Eof]);
}

#[test]
fn shift_disambiguation() {
    assert_eq!(kinds("<<")[..2], [TokenKind::ShiftL, TokenKind::Eof]);
    assert_eq!(kinds("<<=")[..2], [TokenKind::ShiftLAssign, TokenKind::Eof]);
    assert_eq!(kinds(">>")[..2], [TokenKind::ShiftR, TokenKind::Eof]);
    assert_eq!(kinds(">>=")[..2], [TokenKind::ShiftRAssign, TokenKind::Eof]);
}

// ── Compound assignment ──────────────────────────────────────────

#[test]
fn compound_assignment_ops() {
    assert_eq!(kinds("+=")[..2], [TokenKind::PlusAssign, TokenKind::Eof]);
    assert_eq!(kinds("-=")[..2], [TokenKind::MinusAssign, TokenKind::Eof]);
    assert_eq!(kinds("/=")[..2], [TokenKind::SlashAssign, TokenKind::Eof]);
    assert_eq!(kinds("\\=")[..2], [TokenKind::IntDivAssign, TokenKind::Eof]);
    assert_eq!(kinds("%=")[..2], [TokenKind::PercentAssign, TokenKind::Eof]);
    assert_eq!(kinds("&=")[..2], [TokenKind::BitAndAssign, TokenKind::Eof]);
    assert_eq!(kinds("|=")[..2], [TokenKind::BitOrAssign, TokenKind::Eof]);
    assert_eq!(kinds("^=")[..2], [TokenKind::BitXorAssign, TokenKind::Eof]);
}

// ── Increment / decrement ────────────────────────────────────────

#[test]
fn increment_decrement() {
    assert_eq!(
        kinds("i++ j--"),
        vec![
            TokenKind::Ident,
            TokenKind::Increment,
            TokenKind::Ident,
            TokenKind::Decrement,
            TokenKind::Eof,
        ]
    );
}

// ── Bitwise operators ────────────────────────────────────────────

#[test]
fn bitwise_ops() {
    assert_eq!(
        kinds("a & b | c ^ d ~ e"),
        vec![
            TokenKind::Ident,
            TokenKind::BitAnd,
            TokenKind::Ident,
            TokenKind::BitOr,
            TokenKind::Ident,
            TokenKind::BitXor,
            TokenKind::Ident,
            TokenKind::BitNot,
            TokenKind::Ident,
            TokenKind::Eof,
        ]
    );
}

// ── Keywords ─────────────────────────────────────────────────────

#[test]
fn circom_keywords() {
    assert_eq!(
        kinds("signal input output template component var function pragma"),
        vec![
            TokenKind::Signal,
            TokenKind::Input,
            TokenKind::Output,
            TokenKind::Template,
            TokenKind::Component,
            TokenKind::Var,
            TokenKind::Function,
            TokenKind::Pragma,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn control_keywords() {
    assert_eq!(
        kinds("if else for while do return assert log"),
        vec![
            TokenKind::If,
            TokenKind::Else,
            TokenKind::For,
            TokenKind::While,
            TokenKind::Do,
            TokenKind::Return,
            TokenKind::Assert,
            TokenKind::Log,
            TokenKind::Eof,
        ]
    );
}

#[test]
fn modifier_keywords() {
    assert_eq!(
        kinds("parallel custom public bus include main"),
        vec![
            TokenKind::Parallel,
            TokenKind::Custom,
            TokenKind::Public,
            TokenKind::Bus,
            TokenKind::Include,
            TokenKind::MainKw,
            TokenKind::Eof,
        ]
    );
}

// ── Identifiers ──────────────────────────────────────────────────

#[test]
fn dollar_prefix_ident() {
    let tokens = Lexer::tokenize("$special").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::Ident);
    assert_eq!(tokens[0].lexeme, "$special");
}

#[test]
fn underscore_is_special() {
    assert_eq!(kinds("_")[..2], [TokenKind::Underscore, TokenKind::Eof]);
    // But _foo is a regular ident
    let tokens = Lexer::tokenize("_foo").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::Ident);
    assert_eq!(tokens[0].lexeme, "_foo");
}

// ── Numbers ──────────────────────────────────────────────────────

#[test]
fn decimal_number() {
    let tokens = Lexer::tokenize("42").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::DecNumber);
    assert_eq!(tokens[0].lexeme, "42");
}

#[test]
fn hex_number() {
    let tokens = Lexer::tokenize("0xFF").unwrap();
    assert_eq!(tokens[0].kind, TokenKind::HexNumber);
    assert_eq!(tokens[0].lexeme, "0xFF");
}

#[test]
fn hex_no_digits_error() {
    let err = Lexer::tokenize("0x").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E302"));
}

// ── Strings ──────────────────────────────────────────────────────

#[test]
fn string_literal() {
    let tokens = Lexer::tokenize(r#""hello world""#).unwrap();
    assert_eq!(tokens[0].kind, TokenKind::StringLit);
    assert_eq!(tokens[0].lexeme, "hello world");
}

#[test]
fn unterminated_string() {
    let err = Lexer::tokenize(r#""unterminated"#).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}

#[test]
fn string_no_newline() {
    let err = Lexer::tokenize("\"hello\nworld\"").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}

#[test]
fn string_escape_sequences() {
    let tokens = Lexer::tokenize(r#""hello\nworld""#).unwrap();
    assert_eq!(tokens[0].kind, TokenKind::StringLit);
    assert_eq!(tokens[0].lexeme, "hello\nworld");

    let tokens = Lexer::tokenize(r#""tab\there""#).unwrap();
    assert_eq!(tokens[0].lexeme, "tab\there");

    let tokens = Lexer::tokenize(r#""escaped\\backslash""#).unwrap();
    assert_eq!(tokens[0].lexeme, "escaped\\backslash");

    let tokens = Lexer::tokenize(r#""escaped\"quote""#).unwrap();
    assert_eq!(tokens[0].lexeme, "escaped\"quote");
}

#[test]
fn string_invalid_escape() {
    let err = Lexer::tokenize(r#""bad\xescape""#).unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E303"));
}

// ── Comments ─────────────────────────────────────────────────────

#[test]
fn line_comment() {
    assert_eq!(
        kinds("1 // comment\n2"),
        vec![TokenKind::DecNumber, TokenKind::DecNumber, TokenKind::Eof]
    );
}

#[test]
fn block_comment() {
    assert_eq!(
        kinds("1 /* block */ 2"),
        vec![TokenKind::DecNumber, TokenKind::DecNumber, TokenKind::Eof]
    );
}

#[test]
fn unterminated_block_comment() {
    let err = Lexer::tokenize("/* unterminated").unwrap_err();
    assert_eq!(err.code.as_deref(), Some("E301"));
}

// ── Delimiters ───────────────────────────────────────────────────

#[test]
fn delimiters() {
    assert_eq!(
        kinds("()[]{},:;.?"),
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
            TokenKind::Dot,
            TokenKind::Question,
            TokenKind::Eof,
        ]
    );
}

// ── Ternary ──────────────────────────────────────────────────────

#[test]
fn ternary_op() {
    assert_eq!(
        kinds("a ? b : c"),
        vec![
            TokenKind::Ident,
            TokenKind::Question,
            TokenKind::Ident,
            TokenKind::Colon,
            TokenKind::Ident,
            TokenKind::Eof,
        ]
    );
}

// ── Span tracking ────────────────────────────────────────────────

#[test]
fn span_tracking() {
    let tokens = Lexer::tokenize("signal input x;").unwrap();
    // "signal" bytes 0..6
    assert_eq!(tokens[0].span.byte_start, 0);
    assert_eq!(tokens[0].span.byte_end, 6);
    assert_eq!(tokens[0].span.line_start, 1);
    assert_eq!(tokens[0].span.col_start, 1);
    // "input" bytes 7..12
    assert_eq!(tokens[1].span.byte_start, 7);
    assert_eq!(tokens[1].span.byte_end, 12);
    // "x" bytes 13..14
    assert_eq!(tokens[2].span.byte_start, 13);
    assert_eq!(tokens[2].span.byte_end, 14);
}

#[test]
fn multiline_spans() {
    let tokens = Lexer::tokenize("a\nb").unwrap();
    assert_eq!(tokens[0].span.line_start, 1);
    assert_eq!(tokens[1].span.line_start, 2);
}

// ── Realistic Circom snippet ─────────────────────────────────────

#[test]
fn realistic_circom() {
    let src = r#"
pragma circom 2.1.6;
include "circomlib/poseidon.circom";

template Multiplier(n) {
signal input a;
signal input b;
signal output c;
c <== a * b;
}

component main {public [a]} = Multiplier(2);
"#;
    let tokens = Lexer::tokenize(src).unwrap();
    // Should tokenize without error
    assert!(tokens.last().unwrap().kind == TokenKind::Eof);
    // Check key tokens are present
    let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
    assert!(kinds.contains(&&TokenKind::Pragma));
    assert!(kinds.contains(&&TokenKind::Include));
    assert!(kinds.contains(&&TokenKind::Template));
    assert!(kinds.contains(&&TokenKind::Signal));
    assert!(kinds.contains(&&TokenKind::ConstraintAssign));
    assert!(kinds.contains(&&TokenKind::Component));
    assert!(kinds.contains(&&TokenKind::MainKw));
}

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

// ── Integer division ─────────────────────────────────────────────

#[test]
fn int_div_and_assign() {
    assert_eq!(
        kinds("a \\ b")[..4],
        [
            TokenKind::Ident,
            TokenKind::IntDiv,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
    assert_eq!(
        kinds("a \\= b")[..4],
        [
            TokenKind::Ident,
            TokenKind::IntDivAssign,
            TokenKind::Ident,
            TokenKind::Eof
        ]
    );
}
