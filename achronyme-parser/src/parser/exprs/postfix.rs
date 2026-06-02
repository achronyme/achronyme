use crate::ast::{CallArg, Expr};
use crate::error::ParseError;
use crate::token::TokenKind;

use super::Parser;

impl Parser {
    // ========================================================================
    // Postfix helpers
    // ========================================================================

    pub(super) fn parse_call(&mut self, callee: Expr) -> Result<Expr, ParseError> {
        let sp = callee.span().clone();
        self.advance(); // eat `(`

        let mut args = Vec::new();
        let mut seen_keyword = false;

        while !self.at(&TokenKind::RParen) {
            // Detect keyword arg: ident followed by `:` (LL-2 lookahead)
            let is_keyword = matches!(self.peek_kind(), TokenKind::Ident)
                && matches!(self.lookahead(1), TokenKind::Colon);

            if is_keyword {
                let key = self.expect_ident()?;
                self.expect(&TokenKind::Colon)?;
                let val = self.parse_expr()?;
                args.push(CallArg {
                    name: Some(key),
                    value: val,
                });
                seen_keyword = true;
            } else {
                if seen_keyword {
                    let tok = self.peek();
                    return Err(ParseError::new(
                        "positional arguments must come before keyword arguments",
                        tok.span.line_start,
                        tok.span.col_start,
                    ));
                }
                let val = self.parse_expr()?;
                args.push(CallArg {
                    name: None,
                    value: val,
                });
            }

            if self.at(&TokenKind::Comma) {
                self.advance();
            }
        }
        self.expect(&TokenKind::RParen)?;

        let id = self.alloc_expr_id();
        Ok(Expr::Call {
            id,
            callee: Box::new(callee),
            args,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_index(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `[`
        let index = self.parse_expr()?;
        self.expect(&TokenKind::RBracket)?;
        let id = self.alloc_expr_id();
        Ok(Expr::Index {
            id,
            object: Box::new(object),
            index: Box::new(index),
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_dot(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `.`
        let field = self.expect_ident()?;
        let id = self.alloc_expr_id();
        Ok(Expr::DotAccess {
            id,
            object: Box::new(object),
            field,
            span: self.span_to_prev(&sp),
        })
    }
}
