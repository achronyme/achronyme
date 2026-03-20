/// Token types for the Achronyme lexer.
use crate::ast::Span;

/// A single token produced by the lexer.
#[derive(Clone, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub lexeme: String,
}

/// All token variants recognized by the lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // Literals
    Integer,
    FieldLit,
    BigIntLit,
    StringLit,

    // Keywords
    Let,
    Mut,
    If,
    Else,
    While,
    For,
    In,
    Fn,
    Return,
    Break,
    Continue,
    Print,
    Nil,
    True,
    False,
    Public,
    Witness,
    Prove,
    Forever,
    Import,
    Export,
    As,

    // Identifier
    Ident,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Assign,
    Arrow,
    DotDot,
    Dot,

    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    ColonColon,
    Semicolon,

    // End of file
    Eof,
}
