use diagnostics::{Diagnostic, ParseError, Span, SpanRange};

use crate::ast::*;
use crate::token::{Token, TokenKind};

use super::tables::{kind_name, tok_display};

mod top_level;

/// Maximum number of errors before the parser aborts.
const MAX_ERRORS: usize = 20;

pub(super) struct Parser {
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    pub(super) errors: Vec<Diagnostic>,
    pub(super) expr_depth: usize,
    pub(super) block_depth: usize,
}

impl Parser {
    /// Adversarial input like `[[[[...]]]]` blows the recursive-descent
    /// stack before any other limit trips. Cap at 64 to mirror the
    /// `.ach` parser and stay well under the 2 MiB test thread stack.
    pub(super) const MAX_EXPR_DEPTH: usize = 64;

    /// Mirror of `MAX_EXPR_DEPTH` for `{...}` nesting. Adversarial
    /// input like `{{{{...}}}}` would otherwise reach `parse_stmt ->
    /// parse_block` recursion past the test thread stack.
    pub(super) const MAX_BLOCK_DEPTH: usize = 64;

    pub(super) fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            errors: Vec::new(),
            expr_depth: 0,
            block_depth: 0,
        }
    }

    // ====================================================================
    // Token helpers
    // ====================================================================

    pub(super) fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    pub(super) fn peek_kind(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    pub(super) fn at(&self, kind: &TokenKind) -> bool {
        self.peek_kind() == kind
    }

    pub(super) fn advance(&mut self) -> &Token {
        let tok = &self.tokens[self.pos];
        if tok.kind != TokenKind::Eof {
            self.pos += 1;
        }
        tok
    }

    pub(super) fn expect(&mut self, kind: &TokenKind) -> Result<&Token, ParseError> {
        if self.at(kind) {
            Ok(self.advance())
        } else {
            let tok = self.peek();
            Err(ParseError::with_code(
                format!("expected {}, found {}", kind_name(kind), tok_display(tok)),
                "E300",
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    pub(super) fn span(&self) -> Span {
        self.peek().span.clone()
    }

    pub(super) fn prev_span(&self) -> Span {
        if self.pos > 0 {
            self.tokens[self.pos - 1].span.clone()
        } else {
            self.peek().span.clone()
        }
    }

    pub(super) fn span_to_prev(&self, start: &Span) -> Span {
        Span::from_to(start, &self.prev_span())
    }

    pub(super) fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(super) fn lookahead(&self, n: usize) -> &TokenKind {
        let idx = self.pos + n;
        if idx < self.tokens.len() {
            &self.tokens[idx].kind
        } else {
            &TokenKind::Eof
        }
    }

    // ====================================================================
    // Error recovery
    // ====================================================================

    pub(super) fn record_error(&mut self, err: &ParseError) -> bool {
        let mut diag =
            Diagnostic::error(err.message.clone(), SpanRange::point(err.line, err.col, 0));
        if let Some(code) = &err.code {
            diag = diag.with_code(code.clone());
        }
        self.errors.push(diag);
        self.errors.len() >= MAX_ERRORS
    }

    pub(super) fn synchronize(&mut self) {
        loop {
            match self.peek_kind() {
                TokenKind::Eof => break,
                TokenKind::Semicolon => {
                    self.advance();
                    break;
                }
                TokenKind::RBrace => break,
                TokenKind::Signal
                | TokenKind::Var
                | TokenKind::Component
                | TokenKind::Template
                | TokenKind::Function
                | TokenKind::If
                | TokenKind::For
                | TokenKind::While
                | TokenKind::Return
                | TokenKind::Assert
                | TokenKind::Log => break,
                _ => {
                    self.advance();
                }
            }
        }
    }

    pub(super) fn take_errors(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.errors)
    }

    // ====================================================================
    // Block
    // ====================================================================

    pub(super) fn parse_block(&mut self) -> Result<Block, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::LBrace)?;
        if self.block_depth >= Self::MAX_BLOCK_DEPTH {
            let here = self.span();
            return Err(ParseError::with_code(
                format!("block nesting exceeds {} levels", Self::MAX_BLOCK_DEPTH),
                "E300",
                here.line_start,
                here.col_start,
            ));
        }
        self.block_depth += 1;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            match self.parse_stmt() {
                Ok(stmt) => stmts.push(stmt),
                Err(err) => {
                    let error_span = self.span();
                    let abort = self.record_error(&err);
                    self.synchronize();
                    stmts.push(Stmt::Error { span: error_span });
                    if abort {
                        break;
                    }
                }
            }
        }
        self.block_depth -= 1;
        self.expect(&TokenKind::RBrace)?;
        Ok(Block {
            stmts,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    pub(super) fn expect_ident(&mut self) -> Result<String, ParseError> {
        let tok = self.peek();
        if tok.kind == TokenKind::Ident {
            let name = tok.lexeme.clone();
            self.advance();
            Ok(name)
        } else {
            Err(ParseError::with_code(
                format!("expected identifier, found {}", tok_display(tok)),
                "E300",
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    pub(super) fn parse_expr_list(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut exprs = Vec::new();
        if !self.at(&TokenKind::RParen) && !self.at(&TokenKind::RBracket) {
            exprs.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                exprs.push(self.parse_expr()?);
            }
        }
        Ok(exprs)
    }
}
