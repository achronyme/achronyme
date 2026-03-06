use crate::ast::*;
use crate::error::ParseError;
use crate::token::{Token, TokenKind};

use super::tables::{kind_name, tok_display};

pub(super) struct Parser {
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    pub(super) source: String,
    /// Nesting depth: 0 = top-level, >0 = inside block/function.
    pub(super) block_depth: usize,
}

impl Parser {
    pub(super) fn new(tokens: Vec<Token>, source: String) -> Self {
        Self {
            tokens,
            pos: 0,
            source,
            block_depth: 0,
        }
    }

    // ========================================================================
    // Token helpers
    // ========================================================================

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
            Err(ParseError::new(
                format!(
                    "expected `{}`, found `{}`",
                    kind_name(kind),
                    tok_display(tok)
                ),
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    pub(super) fn span(&self) -> Span {
        self.peek().span.clone()
    }

    pub(super) fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Peek at the token N positions ahead (0 = current).
    pub(super) fn lookahead(&self, n: usize) -> &TokenKind {
        let idx = self.pos + n;
        if idx < self.tokens.len() {
            &self.tokens[idx].kind
        } else {
            &TokenKind::Eof
        }
    }

    // ========================================================================
    // Program / Block
    // ========================================================================

    pub(super) fn do_parse_program(&mut self) -> Result<Program, ParseError> {
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
            self.eat(&TokenKind::Semicolon);
        }
        Ok(Program { stmts })
    }

    pub(super) fn do_parse_block(&mut self) -> Result<Block, ParseError> {
        self.parse_block_inner()
    }

    pub(super) fn parse_block_inner(&mut self) -> Result<Block, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::LBrace)?;
        self.block_depth += 1;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
            self.eat(&TokenKind::Semicolon);
        }
        self.block_depth -= 1;
        self.expect(&TokenKind::RBrace)?;
        Ok(Block { stmts, span: sp })
    }
}
