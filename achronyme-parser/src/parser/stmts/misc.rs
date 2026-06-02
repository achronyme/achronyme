use crate::ast::*;
use crate::error::ParseError;
use crate::parser::core::Parser;
use crate::parser::tables::tok_display;
use crate::token::TokenKind;

impl Parser {
    pub(super) fn parse_print(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `print`
        self.expect(&TokenKind::LParen)?;
        let value = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;
        Ok(Stmt::Print {
            value,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `return`
                        // Return has an optional value. Value present if next token can start an expression
                        // and is NOT a statement-starting keyword or block closer.
        let value = if self.can_start_expr() {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Stmt::Return {
            value,
            span: self.span_to_prev(&sp),
        })
    }

    /// Whether the current token can start an expression.
    fn can_start_expr(&self) -> bool {
        matches!(
            self.peek_kind(),
            TokenKind::Integer
                | TokenKind::StringLit
                | TokenKind::Ident
                | TokenKind::True
                | TokenKind::False
                | TokenKind::Nil
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::LBrace
                | TokenKind::Minus
                | TokenKind::Not
                | TokenKind::If
                | TokenKind::While
                | TokenKind::For
                | TokenKind::Forever
                | TokenKind::Fn
                | TokenKind::Prove
        )
    }

    pub(in crate::parser) fn expect_ident(&mut self) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if tok.kind == TokenKind::Ident {
            self.advance();
            Ok(tok.lexeme)
        } else {
            Err(ParseError::new(
                format!("expected identifier, found `{}`", tok_display(&tok)),
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }
}
