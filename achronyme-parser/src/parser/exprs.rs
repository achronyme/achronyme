use crate::ast::*;
use crate::error::ParseError;
use crate::token::TokenKind;

use super::core::Parser;
use super::tables::{infix_bp, is_comparison, tok_display, token_to_binop};

impl Parser {
    // ========================================================================
    // Expressions — Pratt parser
    // ========================================================================

    pub(super) fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_bp(0)
    }

    fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, ParseError> {
        // Prefix
        let mut lhs = self.parse_prefix()?;

        // Infix / postfix loop
        loop {
            // Postfix: call, index, dot
            match self.peek_kind() {
                TokenKind::LParen => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_call(lhs)?;
                    continue;
                }
                TokenKind::LBracket => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_index(lhs)?;
                    continue;
                }
                TokenKind::Dot => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_dot(lhs)?;
                    continue;
                }
                _ => {}
            }

            // Infix binary operators
            if let Some((l_bp, r_bp)) = infix_bp(self.peek_kind()) {
                if l_bp < min_bp {
                    break;
                }
                let op_tok = self.advance().clone();
                let was_cmp = is_comparison(&op_tok.kind);
                let op = token_to_binop(&op_tok.kind);
                let rhs = self.parse_expr_bp(r_bp)?;
                let sp = lhs.span().clone();
                lhs = Expr::BinOp {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span: sp,
                };
                // Reject chained comparisons: `a < b < c` is a silent bug
                if was_cmp && is_comparison(self.peek_kind()) {
                    let next = self.peek();
                    return Err(ParseError::new(
                        "comparison operators cannot be chained; use `&&` to combine: `a < b && b < c`",
                        next.span.line,
                        next.span.col,
                    ));
                }
                continue;
            }

            break;
        }

        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<Expr, ParseError> {
        match self.peek_kind() {
            TokenKind::Minus | TokenKind::Not => {
                let sp = self.span();
                let op_tok = self.advance().clone();
                let op = match op_tok.kind {
                    TokenKind::Minus => UnaryOp::Neg,
                    TokenKind::Not => UnaryOp::Not,
                    _ => unreachable!(),
                };
                let operand = self.parse_expr_bp(11)?; // prefix BP
                Ok(Expr::UnaryOp {
                    op,
                    operand: Box::new(operand),
                    span: sp,
                })
            }
            _ => self.parse_atom(),
        }
    }

    fn parse_atom(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        match self.peek_kind().clone() {
            TokenKind::Integer => {
                let tok = self.advance().clone();
                Ok(Expr::Number {
                    value: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::FieldLit => {
                let tok = self.advance().clone();
                let (value, radix) = if let Some(hex) = tok.lexeme.strip_prefix('x') {
                    (hex.to_string(), FieldRadix::Hex)
                } else if let Some(bin) = tok.lexeme.strip_prefix('b') {
                    (bin.to_string(), FieldRadix::Binary)
                } else {
                    (tok.lexeme, FieldRadix::Decimal)
                };
                Ok(Expr::FieldLit {
                    value,
                    radix,
                    span: sp,
                })
            }
            TokenKind::BigIntLit => {
                let tok = self.advance().clone();
                // Lexeme format: "256xFF00" or "512d42" or "256b1010"
                // Find the radix char position (first non-digit after start)
                let width_end = tok
                    .lexeme
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(tok.lexeme.len());
                let width: u16 = tok.lexeme[..width_end]
                    .parse()
                    .map_err(|_| ParseError::new("invalid BigInt width", sp.line, sp.col))?;
                let rest = &tok.lexeme[width_end..];
                let (value, radix) = if let Some(hex) = rest.strip_prefix('x') {
                    (hex.to_string(), BigIntRadix::Hex)
                } else if let Some(dec) = rest.strip_prefix('d') {
                    (dec.to_string(), BigIntRadix::Decimal)
                } else if let Some(bin) = rest.strip_prefix('b') {
                    (bin.to_string(), BigIntRadix::Binary)
                } else {
                    return Err(ParseError::new(
                        "invalid BigInt literal radix",
                        sp.line,
                        sp.col,
                    ));
                };
                Ok(Expr::BigIntLit {
                    value,
                    width,
                    radix,
                    span: sp,
                })
            }
            TokenKind::StringLit => {
                let tok = self.advance().clone();
                Ok(Expr::StringLit {
                    value: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Bool {
                    value: true,
                    span: sp,
                })
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Bool {
                    value: false,
                    span: sp,
                })
            }
            TokenKind::Nil => {
                self.advance();
                Ok(Expr::Nil { span: sp })
            }
            TokenKind::Ident => {
                let tok = self.advance().clone();
                Ok(Expr::Ident {
                    name: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&TokenKind::RParen)?;
                Ok(expr)
            }
            TokenKind::LBracket => self.parse_array(),
            TokenKind::LBrace => self.parse_brace_expr(),
            TokenKind::If => self.parse_if(),
            TokenKind::While => self.parse_while(),
            TokenKind::For => self.parse_for(),
            TokenKind::Forever => self.parse_forever(),
            TokenKind::Fn => self.parse_fn_expr(),
            TokenKind::Prove => self.parse_prove(),
            _ => {
                let tok = self.peek();
                Err(ParseError::new(
                    format!("expected expression, found `{}`", tok_display(tok)),
                    tok.span.line,
                    tok.span.col,
                ))
            }
        }
    }

    // ========================================================================
    // Postfix helpers
    // ========================================================================

    fn parse_call(&mut self, callee: Expr) -> Result<Expr, ParseError> {
        let sp = callee.span().clone();
        self.advance(); // eat `(`
        let mut args = Vec::new();
        if !self.at(&TokenKind::RParen) {
            args.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RParen) {
                    break; // trailing comma
                }
                args.push(self.parse_expr()?);
            }
        }
        self.expect(&TokenKind::RParen)?;
        Ok(Expr::Call {
            callee: Box::new(callee),
            args,
            span: sp,
        })
    }

    fn parse_index(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `[`
        let index = self.parse_expr()?;
        self.expect(&TokenKind::RBracket)?;
        Ok(Expr::Index {
            object: Box::new(object),
            index: Box::new(index),
            span: sp,
        })
    }

    fn parse_dot(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `.`
        let field = self.expect_ident()?;
        Ok(Expr::DotAccess {
            object: Box::new(object),
            field,
            span: sp,
        })
    }

    // ========================================================================
    // Compound expressions
    // ========================================================================

    fn parse_array(&mut self) -> Result<Expr, ParseError> {
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
        Ok(Expr::Array { elements, span: sp })
    }

    /// Disambiguate `{` — map literal vs block.
    /// Map: `{ ident: expr, ... }` or `{ "str": expr, ... }`
    /// Block: everything else
    fn parse_brace_expr(&mut self) -> Result<Expr, ParseError> {
        // LL-3 lookahead: `{ (ident|string) `:` → map
        if self.is_map_literal() {
            self.parse_map()
        } else {
            let block = self.parse_block_inner()?;
            Ok(Expr::Block(block))
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
        Ok(Expr::Map { pairs, span: sp })
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
                    tok.span.line,
                    tok.span.col,
                ));
            }
        };
        self.expect(&TokenKind::Colon)?;
        let value = self.parse_expr()?;
        Ok((key, value))
    }

    fn parse_if(&mut self) -> Result<Expr, ParseError> {
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
        Ok(Expr::If {
            condition,
            then_block,
            else_branch,
            span: sp,
        })
    }

    fn parse_while(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `while`
        let condition = Box::new(self.parse_expr()?);
        let body = self.parse_block_inner()?;
        Ok(Expr::While {
            condition,
            body,
            span: sp,
        })
    }

    fn parse_for(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `for`
        let var = self.expect_ident()?;
        self.expect(&TokenKind::In)?;

        // Try range: `integer..integer`
        let iterable = if self.at(&TokenKind::Integer) && self.lookahead(1) == &TokenKind::DotDot {
            let start_tok = self.advance().clone();
            self.advance(); // eat `..`
            let end_tok = self.expect(&TokenKind::Integer)?;
            let start: u64 = start_tok.lexeme.parse().map_err(|e| {
                ParseError::new(
                    format!("invalid range start: {e}"),
                    start_tok.span.line,
                    start_tok.span.col,
                )
            })?;
            let end: u64 = end_tok.lexeme.parse().map_err(|e| {
                ParseError::new(
                    format!("invalid range end: {e}"),
                    end_tok.span.line,
                    end_tok.span.col,
                )
            })?;
            ForIterable::Range { start, end }
        } else {
            ForIterable::Expr(Box::new(self.parse_expr()?))
        };

        let body = self.parse_block_inner()?;
        Ok(Expr::For {
            var,
            iterable,
            body,
            span: sp,
        })
    }

    fn parse_forever(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `forever`
        let body = self.parse_block_inner()?;
        Ok(Expr::Forever { body, span: sp })
    }

    fn parse_fn_expr(&mut self) -> Result<Expr, ParseError> {
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
        Ok(Expr::FnExpr {
            name,
            params,
            return_type,
            body,
            span: sp,
        })
    }

    fn parse_prove(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        let start = self.peek().byte_offset;
        self.advance(); // eat `prove`

        let body = self.parse_block_inner()?;

        // The closing `}` was the token just before current position
        let end = self.tokens[self.pos - 1].byte_offset + 1;
        let source_text = self.source[start..end].to_string();

        Ok(Expr::Prove {
            body,
            source: source_text,
            span: sp,
        })
    }
}
