use crate::ast::*;
use crate::error::ParseError;
use crate::token::TokenKind;

use super::Parser;
use crate::parser::tables::tok_display;

impl Parser {
    // ========================================================================
    // Compound expressions
    // ========================================================================

    pub(super) fn parse_array(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `[`
        let mut elements = Vec::new();
        if !self.at(&TokenKind::RBracket) {
            elements.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RBracket) {
                    break; // trailing comma
                }
                elements.push(self.parse_expr()?);
            }
        }
        self.expect(&TokenKind::RBracket)?;
        let id = self.alloc_expr_id();
        Ok(Expr::Array {
            id,
            elements,
            span: self.span_to_prev(&sp),
        })
    }

    /// Disambiguate `{` — map literal vs block.
    /// Map: `{ ident: expr, ... }` or `{ "str": expr, ... }`
    /// Block: everything else
    pub(super) fn parse_brace_expr(&mut self) -> Result<Expr, ParseError> {
        // LL-3 lookahead: `{ (ident|string) `:` → map
        if self.is_map_literal() {
            self.parse_map()
        } else {
            let block = self.parse_block_inner()?;
            let id = self.alloc_expr_id();
            Ok(Expr::Block { id, block })
        }
    }

    fn is_map_literal(&self) -> bool {
        // Current token is `{`
        // Check tokens[pos+1] is ident or string, and tokens[pos+2] is `:`
        match self.lookahead(1) {
            TokenKind::Ident | TokenKind::StringLit => {
                matches!(self.lookahead(2), TokenKind::Colon)
            }
            // `{}` is an empty map (matches pest grammar behavior)
            TokenKind::RBrace => true,
            _ => false,
        }
    }

    fn parse_map(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `{`
        let mut pairs = Vec::new();
        if !self.at(&TokenKind::RBrace) {
            pairs.push(self.parse_map_pair()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RBrace) {
                    break; // trailing comma
                }
                pairs.push(self.parse_map_pair()?);
            }
        }
        self.expect(&TokenKind::RBrace)?;
        let id = self.alloc_expr_id();
        Ok(Expr::Map {
            id,
            pairs,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_map_pair(&mut self) -> Result<(MapKey, Expr), ParseError> {
        let key = match self.peek_kind() {
            TokenKind::Ident => {
                let tok = self.advance().clone();
                MapKey::Ident(tok.lexeme)
            }
            TokenKind::StringLit => {
                let tok = self.advance().clone();
                MapKey::StringLit(tok.lexeme)
            }
            _ => {
                let tok = self.peek();
                return Err(ParseError::new(
                    format!(
                        "expected map key (identifier or string), found `{}`",
                        tok_display(tok)
                    ),
                    tok.span.line_start,
                    tok.span.col_start,
                ));
            }
        };
        self.expect(&TokenKind::Colon)?;
        let value = self.parse_expr()?;
        Ok((key, value))
    }

    pub(super) fn parse_if(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `if`
        let condition = Box::new(self.parse_expr()?);
        let then_block = self.parse_block_inner()?;
        let else_branch = if self.eat(&TokenKind::Else) {
            if self.at(&TokenKind::If) {
                Some(ElseBranch::If(Box::new(self.parse_if()?)))
            } else {
                Some(ElseBranch::Block(self.parse_block_inner()?))
            }
        } else {
            None
        };
        let id = self.alloc_expr_id();
        Ok(Expr::If {
            id,
            condition,
            then_block,
            else_branch,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_while(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `while`
        let condition = Box::new(self.parse_expr()?);
        let body = self.parse_block_inner()?;
        let id = self.alloc_expr_id();
        Ok(Expr::While {
            id,
            condition,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_for(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `for`
        let var = self.expect_ident()?;
        self.expect(&TokenKind::In)?;

        // Try range: `integer..integer` or `integer..expr`
        let iterable = if self.at(&TokenKind::Integer) && self.lookahead(1) == &TokenKind::DotDot {
            let start_tok = self.advance().clone();
            self.advance(); // eat `..`
            let start: u64 = start_tok.lexeme.parse().map_err(|e| {
                ParseError::new(
                    format!("invalid range start: {e}"),
                    start_tok.span.line_start,
                    start_tok.span.col_start,
                )
            })?;
            if self.at(&TokenKind::Integer) {
                // Literal end bound: `0..5`
                let end_tok = self.advance().clone();
                let end: u64 = end_tok.lexeme.parse().map_err(|e| {
                    ParseError::new(
                        format!("invalid range end: {e}"),
                        end_tok.span.line_start,
                        end_tok.span.col_start,
                    )
                })?;
                ForIterable::Range { start, end }
            } else {
                // Expression end bound: `0..n`, `0..n+1`, `0..(n*2)`
                let end_expr = self.parse_expr()?;
                ForIterable::ExprRange {
                    start,
                    end: Box::new(end_expr),
                }
            }
        } else {
            ForIterable::Expr(Box::new(self.parse_expr()?))
        };

        let body = self.parse_block_inner()?;
        let id = self.alloc_expr_id();
        Ok(Expr::For {
            id,
            var,
            iterable,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_forever(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `forever`
        let body = self.parse_block_inner()?;
        let id = self.alloc_expr_id();
        Ok(Expr::Forever {
            id,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_fn_expr(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `fn`
        let name = if self.at(&TokenKind::Ident) {
            Some(self.expect_ident()?)
        } else {
            None
        };
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(&TokenKind::RParen)?;
        let return_type = self.try_parse_return_type()?;
        let body = self.parse_block_inner()?;
        let id = self.alloc_expr_id();
        Ok(Expr::FnExpr {
            id,
            name,
            params,
            return_type,
            body,
            span: self.span_to_prev(&sp),
        })
    }
}
