use crate::ast::BinOp;
use crate::token::{Token, TokenKind};

/// Returns true if the token kind is a comparison operator.
pub(super) fn is_comparison(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Eq
            | TokenKind::Neq
            | TokenKind::Lt
            | TokenKind::Le
            | TokenKind::Gt
            | TokenKind::Ge
    )
}

/// Returns (left_bp, right_bp) for infix operators. None if not infix.
pub(super) fn infix_bp(kind: &TokenKind) -> Option<(u8, u8)> {
    Some(match kind {
        TokenKind::Or => (1, 2),
        TokenKind::And => (3, 4),
        TokenKind::Eq
        | TokenKind::Neq
        | TokenKind::Lt
        | TokenKind::Le
        | TokenKind::Gt
        | TokenKind::Ge => (5, 6),
        TokenKind::Plus | TokenKind::Minus => (7, 8),
        TokenKind::Star | TokenKind::Slash | TokenKind::Percent => (9, 10),
        TokenKind::Caret => (12, 11), // right-associative
        _ => return None,
    })
}

pub(super) fn token_to_binop(kind: &TokenKind) -> BinOp {
    match kind {
        TokenKind::Plus => BinOp::Add,
        TokenKind::Minus => BinOp::Sub,
        TokenKind::Star => BinOp::Mul,
        TokenKind::Slash => BinOp::Div,
        TokenKind::Percent => BinOp::Mod,
        TokenKind::Caret => BinOp::Pow,
        TokenKind::Eq => BinOp::Eq,
        TokenKind::Neq => BinOp::Neq,
        TokenKind::Lt => BinOp::Lt,
        TokenKind::Le => BinOp::Le,
        TokenKind::Gt => BinOp::Gt,
        TokenKind::Ge => BinOp::Ge,
        TokenKind::And => BinOp::And,
        TokenKind::Or => BinOp::Or,
        _ => unreachable!("not a binary operator: {kind:?}"),
    }
}

pub(super) fn kind_name(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Integer => "integer",
        TokenKind::FieldLit => "field literal",
        TokenKind::BigIntLit => "bigint literal",
        TokenKind::StringLit => "string",
        TokenKind::Let => "let",
        TokenKind::Mut => "mut",
        TokenKind::If => "if",
        TokenKind::Else => "else",
        TokenKind::While => "while",
        TokenKind::For => "for",
        TokenKind::In => "in",
        TokenKind::Fn => "fn",
        TokenKind::Return => "return",
        TokenKind::Break => "break",
        TokenKind::Continue => "continue",
        TokenKind::Print => "print",
        TokenKind::Nil => "nil",
        TokenKind::True => "true",
        TokenKind::False => "false",
        TokenKind::Public => "public",
        TokenKind::Witness => "witness",
        TokenKind::Prove => "prove",
        TokenKind::Forever => "forever",
        TokenKind::Import => "import",
        TokenKind::Export => "export",
        TokenKind::As => "as",
        TokenKind::Ident => "identifier",
        TokenKind::Plus => "+",
        TokenKind::Minus => "-",
        TokenKind::Star => "*",
        TokenKind::Slash => "/",
        TokenKind::Percent => "%",
        TokenKind::Caret => "^",
        TokenKind::Eq => "==",
        TokenKind::Neq => "!=",
        TokenKind::Lt => "<",
        TokenKind::Le => "<=",
        TokenKind::Gt => ">",
        TokenKind::Ge => ">=",
        TokenKind::And => "&&",
        TokenKind::Or => "||",
        TokenKind::Not => "!",
        TokenKind::Assign => "=",
        TokenKind::Arrow => "->",
        TokenKind::DotDot => "..",
        TokenKind::Dot => ".",
        TokenKind::LParen => "(",
        TokenKind::RParen => ")",
        TokenKind::LBracket => "[",
        TokenKind::RBracket => "]",
        TokenKind::LBrace => "{",
        TokenKind::RBrace => "}",
        TokenKind::Comma => ",",
        TokenKind::Colon => ":",
        TokenKind::Semicolon => ";",
        TokenKind::Eof => "end of file",
    }
}

pub(super) fn tok_display(tok: &Token) -> String {
    if tok.kind == TokenKind::Eof {
        "end of file".to_string()
    } else if tok.lexeme.is_empty() {
        kind_name(&tok.kind).to_string()
    } else {
        tok.lexeme.clone()
    }
}
