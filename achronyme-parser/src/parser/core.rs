use crate::ast::*;
use crate::diagnostic::{Diagnostic, SpanRange};
use crate::error::ParseError;
use crate::token::{Token, TokenKind};

use super::tables::{kind_name, tok_display};

/// Maximum number of errors before the parser aborts.
const MAX_ERRORS: usize = 20;

pub(super) struct Parser {
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    /// Nesting depth: 0 = top-level, >0 = inside block/function.
    pub(super) block_depth: usize,
    /// Expression parser recursion depth. Tracked separately from
    /// `block_depth` because expression nesting (`[[[...]]]`,
    /// `((((...))))`, chained postfix) can blow the stack without
    /// ever entering a block. Bumped on `parse_expr_bp` entry.
    pub(super) expr_depth: usize,
    /// Collected diagnostics from error recovery.
    pub(super) errors: Vec<Diagnostic>,
    /// Monotonic counter used to assign every constructed `Expr` a
    /// unique [`ExprId`]. Starts at 0 and is pre-incremented in
    /// [`alloc_expr_id`], so the first allocated id is `ExprId(1)` —
    /// never the reserved [`ExprId::SYNTHETIC`] (which is `0`).
    pub(super) next_expr_id: u32,
}

impl Parser {
    /// Maximum expression parser recursion depth. Adversarial input
    /// like `[[[[...]]]` would otherwise overflow the stack before
    /// hitting any block-level cap. 128 stays well under a 2 MB test
    /// thread stack even in debug builds under ASAN.
    pub(super) const MAX_EXPR_DEPTH: usize = 128;

    pub(super) fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            block_depth: 0,
            expr_depth: 0,
            errors: Vec::new(),
            next_expr_id: 0,
        }
    }

    /// Allocate a fresh, unique [`ExprId`] for the next `Expr` being
    /// constructed. Caller must wire the returned id into the `id`
    /// field of the `Expr` variant.
    ///
    /// Id allocation is monotonic but has **no required relationship
    /// with source order** — some expressions allocate their id after
    /// parsing their sub-expressions (e.g. `BinOp` and postfix chains),
    /// so an outer expression may have a larger id than its own
    /// operands. The only invariants the resolver relies on are
    /// uniqueness and non-zero.
    pub(super) fn alloc_expr_id(&mut self) -> ExprId {
        self.next_expr_id = self
            .next_expr_id
            .checked_add(1)
            .expect("parser allocated more than u32::MAX expression ids");
        ExprId::from_raw(self.next_expr_id)
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

    /// Return the span of the most recently consumed token.
    pub(super) fn prev_span(&self) -> Span {
        if self.pos > 0 {
            self.tokens[self.pos - 1].span.clone()
        } else {
            self.peek().span.clone()
        }
    }

    /// Build a span from `start` to the most recently consumed token.
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
    // Error recovery
    // ========================================================================

    /// Record a parse error as a diagnostic and check the error limit.
    /// Returns `true` if the parser should abort (too many errors).
    pub(super) fn record_error(&mut self, err: &ParseError) -> bool {
        let diag = Diagnostic::error(err.message.clone(), SpanRange::point(err.line, err.col, 0));
        self.errors.push(diag);
        self.errors.len() >= MAX_ERRORS
    }

    /// Skip tokens until a synchronization point is found.
    /// Sync tokens: `;`, `}`, `fn`, `let`, `mut`, `public`, `witness`, `import`, `export`, `EOF`.
    pub(super) fn synchronize(&mut self) {
        loop {
            match self.peek_kind() {
                TokenKind::Eof => break,
                TokenKind::Semicolon => {
                    self.advance(); // consume the `;`
                    break;
                }
                TokenKind::RBrace => {
                    // Don't consume — let block-closing logic handle it
                    break;
                }
                TokenKind::Fn
                | TokenKind::Let
                | TokenKind::Mut
                | TokenKind::Public
                | TokenKind::Witness
                | TokenKind::Import
                | TokenKind::Export => {
                    // Don't consume — this starts the next statement
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Take all collected errors, leaving the internal vec empty.
    pub(super) fn take_errors(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.errors)
    }

    // ========================================================================
    // Program / Block
    // ========================================================================

    pub(super) fn do_parse_program(&mut self) -> Result<Program, ParseError> {
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::Eof) {
            match self.parse_stmt() {
                Ok(stmt) => {
                    stmts.push(stmt);
                }
                Err(err) => {
                    let error_span = self.span();
                    let abort = self.record_error(&err);
                    self.synchronize();
                    stmts.push(Stmt::Error { span: error_span });
                    if abort {
                        break;
                    }
                    continue;
                }
            }
            self.eat(&TokenKind::Semicolon);
        }
        Ok(Program { stmts })
    }

    pub(super) fn do_parse_block(&mut self) -> Result<Block, ParseError> {
        self.parse_block_inner()
    }

    pub(super) fn parse_block_inner(&mut self) -> Result<Block, ParseError> {
        // Each nested block frame carries parse_stmt + parse_expr +
        // parse_brace_expr on the stack (several KB per level in
        // debug builds with ASAN). 64 is conservative enough to stay
        // under a 2 MB default test thread stack with room to spare;
        // legitimate programs never nest this deeply.
        const MAX_BLOCK_DEPTH: usize = 64;
        let sp = self.span();
        self.expect(&TokenKind::LBrace)?;
        if self.block_depth >= MAX_BLOCK_DEPTH {
            // Stop before the recursive parse_stmt call blows the
            // stack. Adversarial inputs like `{{{{...}}}}` would
            // otherwise trigger an ASAN-detectable overflow (caught
            // by fuzz_parser). A legitimate program never nests
            // blocks this deeply; bail with a diagnostic instead.
            let sp = self.span();
            return Err(ParseError::new(
                format!("block nesting exceeds {MAX_BLOCK_DEPTH} levels"),
                sp.line_start,
                sp.col_start,
            ));
        }
        self.block_depth += 1;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            match self.parse_stmt() {
                Ok(stmt) => {
                    stmts.push(stmt);
                }
                Err(err) => {
                    let error_span = self.span();
                    let abort = self.record_error(&err);
                    self.synchronize();
                    stmts.push(Stmt::Error { span: error_span });
                    if abort {
                        break;
                    }
                    continue;
                }
            }
            self.eat(&TokenKind::Semicolon);
        }
        self.block_depth -= 1;
        self.expect(&TokenKind::RBrace)?;
        Ok(Block {
            stmts,
            span: self.span_to_prev(&sp),
        })
    }
}
