use diagnostics::{Diagnostic, ParseError, Span, SpanRange};

use crate::ast::*;
use crate::token::{Token, TokenKind};

use super::tables::{kind_name, tok_display};

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
    // Program
    // ====================================================================

    pub(super) fn do_parse_program(&mut self) -> Result<CircomProgram, ParseError> {
        let mut version = None;
        let mut custom_templates = false;
        let mut includes = Vec::new();
        let mut definitions = Vec::new();
        let mut main_component = None;

        // Parse pragmas
        while self.at(&TokenKind::Pragma) {
            let pragma = self.parse_pragma()?;
            match pragma {
                Pragma::Version(v) => version = Some(v),
                Pragma::CustomTemplates => custom_templates = true,
            }
        }

        // Parse includes
        while self.at(&TokenKind::Include) {
            includes.push(self.parse_include()?);
        }

        // Parse definitions and main component
        while !self.at(&TokenKind::Eof) {
            match self.peek_kind() {
                TokenKind::Template => {
                    definitions.push(Definition::Template(self.parse_template_def()?));
                }
                TokenKind::Function => {
                    definitions.push(Definition::Function(self.parse_function_def()?));
                }
                TokenKind::Bus => {
                    definitions.push(Definition::Bus(self.parse_bus_def()?));
                }
                TokenKind::Component => {
                    // Could be `component main ...`
                    if self.lookahead(1) == &TokenKind::MainKw {
                        main_component = Some(self.parse_main_component()?);
                    } else {
                        // Unexpected top-level component — error recovery
                        let err = ParseError::with_code(
                            "unexpected `component` at top level (did you mean `component main`?)",
                            "E306",
                            self.peek().span.line_start,
                            self.peek().span.col_start,
                        );
                        let abort = self.record_error(&err);
                        self.synchronize();
                        if abort {
                            break;
                        }
                    }
                }
                _ => {
                    let tok = self.peek();
                    let err = ParseError::with_code(
                        format!(
                            "expected `template`, `function`, `bus`, or `component main`, found {}",
                            tok_display(tok)
                        ),
                        "E306",
                        tok.span.line_start,
                        tok.span.col_start,
                    );
                    let abort = self.record_error(&err);
                    self.synchronize();
                    if abort {
                        break;
                    }
                }
            }
        }

        Ok(CircomProgram {
            version,
            custom_templates,
            includes,
            definitions,
            main_component,
        })
    }

    // ====================================================================
    // Pragmas
    // ====================================================================

    fn parse_pragma(&mut self) -> Result<Pragma, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Pragma)?;

        let tok = self.peek();
        match tok.lexeme.as_str() {
            "circom" => {
                self.advance();
                let version = self.parse_version(&sp)?;
                self.expect(&TokenKind::Semicolon)?;
                Ok(Pragma::Version(version))
            }
            "custom_templates" => {
                self.advance();
                self.expect(&TokenKind::Semicolon)?;
                Ok(Pragma::CustomTemplates)
            }
            _ => Err(ParseError::with_code(
                format!("unknown pragma `{}`", tok.lexeme),
                "E304",
                tok.span.line_start,
                tok.span.col_start,
            )),
        }
    }

    fn parse_version(&mut self, start: &Span) -> Result<Version, ParseError> {
        let major = self.expect_number()?;
        self.expect(&TokenKind::Dot)?;
        let minor = self.expect_number()?;
        self.expect(&TokenKind::Dot)?;
        let patch = self.expect_number()?;
        Ok(Version {
            major,
            minor,
            patch,
            span: self.span_to_prev(start),
        })
    }

    fn expect_number(&mut self) -> Result<u32, ParseError> {
        let tok = self.peek();
        if tok.kind == TokenKind::DecNumber {
            let val = tok.lexeme.parse::<u32>().map_err(|_| {
                ParseError::with_code(
                    format!("invalid version number `{}`", tok.lexeme),
                    "E305",
                    tok.span.line_start,
                    tok.span.col_start,
                )
            })?;
            self.advance();
            Ok(val)
        } else {
            Err(ParseError::with_code(
                format!("expected version number, found {}", tok_display(tok)),
                "E305",
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    // ====================================================================
    // Includes
    // ====================================================================

    fn parse_include(&mut self) -> Result<Include, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Include)?;
        let tok = self.peek();
        if tok.kind != TokenKind::StringLit {
            return Err(ParseError::with_code(
                format!(
                    "expected string after `include`, found {}",
                    tok_display(tok)
                ),
                "E300",
                tok.span.line_start,
                tok.span.col_start,
            ));
        }
        let path = tok.lexeme.clone();
        self.advance();
        self.expect(&TokenKind::Semicolon)?;
        Ok(Include {
            path,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Definitions
    // ====================================================================

    fn parse_template_def(&mut self) -> Result<TemplateDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Template)?;

        let mut modifiers = TemplateModifiers::default();

        // Parse optional modifiers: custom, parallel, extern_c (in any order)
        loop {
            match self.peek_kind() {
                TokenKind::Custom => {
                    self.advance();
                    modifiers.custom = true;
                }
                TokenKind::Parallel => {
                    self.advance();
                    modifiers.parallel = true;
                }
                // `extern_c` is not a keyword — it's an identifier (v2.2.3+)
                TokenKind::Ident if self.peek().lexeme == "extern_c" => {
                    self.advance();
                    modifiers.extern_c = true;
                }
                _ => break,
            }
        }

        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(TemplateDef {
            name,
            params,
            modifiers,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_function_def(&mut self) -> Result<FunctionDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Function)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(FunctionDef {
            name,
            params,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_bus_def(&mut self) -> Result<BusDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Bus)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(BusDef {
            name,
            params,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_main_component(&mut self) -> Result<MainComponent, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Component)?;
        self.expect(&TokenKind::MainKw)?;

        // Optional {public [sig1, sig2]}
        let mut public_signals = Vec::new();
        if self.eat(&TokenKind::LBrace) {
            self.expect(&TokenKind::Public)?;
            self.expect(&TokenKind::LBracket)?;
            public_signals = self.parse_ident_list()?;
            self.expect(&TokenKind::RBracket)?;
            self.expect(&TokenKind::RBrace)?;
        }

        self.expect(&TokenKind::Assign)?;

        let template_name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let template_args = self.parse_expr_list()?;
        self.expect(&TokenKind::RParen)?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(MainComponent {
            public_signals,
            template_name,
            template_args,
            span: self.span_to_prev(&sp),
        })
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

    fn parse_ident_list(&mut self) -> Result<Vec<String>, ParseError> {
        let mut names = Vec::new();
        if !self.at(&TokenKind::RParen) && !self.at(&TokenKind::RBracket) {
            names.push(self.expect_ident()?);
            while self.eat(&TokenKind::Comma) {
                names.push(self.expect_ident()?);
            }
        }
        Ok(names)
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

/// Internal pragma representation.
enum Pragma {
    Version(Version),
    CustomTemplates,
}
