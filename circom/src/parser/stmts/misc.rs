use diagnostics::ParseError;

use crate::ast::*;
use crate::token::TokenKind;

use super::super::core::Parser;

impl Parser {
    pub(super) fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Return)?;
        let value = self.parse_expr()?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::Return {
            value,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_assert(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Assert)?;
        self.expect(&TokenKind::LParen)?;
        let arg = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::Assert {
            arg,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_log(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Log)?;
        self.expect(&TokenKind::LParen)?;

        let mut args = Vec::new();
        if !self.at(&TokenKind::RParen) {
            args.push(self.parse_log_arg()?);
            while self.eat(&TokenKind::Comma) {
                args.push(self.parse_log_arg()?);
            }
        }

        self.expect(&TokenKind::RParen)?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::Log {
            args,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_log_arg(&mut self) -> Result<LogArg, ParseError> {
        if self.at(&TokenKind::StringLit) {
            let tok = self.peek();
            let s = tok.lexeme.clone();
            let span = tok.span.clone();
            self.advance();
            Ok(LogArg::String(s, span))
        } else {
            Ok(LogArg::Expr(self.parse_expr()?))
        }
    }
}
