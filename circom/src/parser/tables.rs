use crate::token::{Token, TokenKind};

/// Human-readable token kind name for error messages.
pub(super) fn kind_name(kind: &TokenKind) -> &'static str {
    kind.name()
}

/// Display a token for error messages (shows lexeme for identifiers/numbers).
pub(super) fn tok_display(tok: &Token) -> String {
    match tok.kind {
        TokenKind::Ident => format!("`{}`", tok.lexeme),
        TokenKind::DecNumber | TokenKind::HexNumber => format!("`{}`", tok.lexeme),
        TokenKind::StringLit => format!("\"{}\"", tok.lexeme),
        TokenKind::Eof => "end of file".to_string(),
        _ => kind_name(&tok.kind).to_string(),
    }
}
