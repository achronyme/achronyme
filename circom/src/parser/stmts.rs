use diagnostics::ParseError;

use crate::ast::*;
use crate::token::TokenKind;

use super::core::Parser;

mod control;
mod declarations;
mod expr_substitution;
mod misc;

impl Parser {
    /// Parse a single statement.
    pub(super) fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek_kind() {
            TokenKind::Signal => self.parse_signal_decl(),
            TokenKind::Input | TokenKind::Output => self.parse_signal_decl_reversed(),
            TokenKind::Var => self.parse_var_decl(),
            TokenKind::Component => self.parse_component_decl(),
            TokenKind::If => self.parse_if_else(),
            TokenKind::For => self.parse_for(),
            TokenKind::While => self.parse_while(),
            TokenKind::Do => self.parse_do_while(),
            TokenKind::Return => self.parse_return(),
            TokenKind::Assert => self.parse_assert(),
            TokenKind::Log => self.parse_log(),
            TokenKind::LBrace => Ok(Stmt::Block(self.parse_block()?)),
            _ => self.parse_expr_or_substitution(),
        }
    }
}
