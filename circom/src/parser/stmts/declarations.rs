use diagnostics::ParseError;

use crate::ast::*;
use crate::token::TokenKind;

use super::super::core::Parser;

impl Parser {
    // ====================================================================
    // Signal declarations
    // ====================================================================

    /// `signal [input|output] [{tags}] name[dims]... [<== expr | <-- expr];`
    pub(super) fn parse_signal_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Signal)?;

        let signal_type = match self.peek_kind() {
            TokenKind::Input => {
                self.advance();
                SignalType::Input
            }
            TokenKind::Output => {
                self.advance();
                SignalType::Output
            }
            _ => SignalType::Intermediate,
        };

        // Optional tags: {tag1, tag2}
        let tags = if self.eat(&TokenKind::LBrace) {
            let mut tags = Vec::new();
            if !self.at(&TokenKind::RBrace) {
                tags.push(self.expect_ident()?);
                while self.eat(&TokenKind::Comma) {
                    tags.push(self.expect_ident()?);
                }
            }
            self.expect(&TokenKind::RBrace)?;
            tags
        } else {
            Vec::new()
        };

        // Parse signal names with optional array dimensions
        let mut declarations = Vec::new();
        declarations.push(self.parse_signal_name()?);
        while self.eat(&TokenKind::Comma) {
            declarations.push(self.parse_signal_name()?);
        }

        // Optional init: <== expr or <-- expr
        let init = match self.peek_kind() {
            TokenKind::ConstraintAssign => {
                self.advance();
                let expr = self.parse_expr()?;
                Some((AssignOp::ConstraintAssign, expr))
            }
            TokenKind::SignalAssign => {
                self.advance();
                let expr = self.parse_expr()?;
                Some((AssignOp::SignalAssign, expr))
            }
            _ => None,
        };

        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::SignalDecl {
            signal_type,
            tags,
            declarations,
            init,
            span: self.span_to_prev(&sp),
        })
    }

    /// `input signal ...` or `output signal ...` (Circom 2.2.0+ reversed order)
    pub(super) fn parse_signal_decl_reversed(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        let signal_type = match self.peek_kind() {
            TokenKind::Input => {
                self.advance();
                SignalType::Input
            }
            TokenKind::Output => {
                self.advance();
                SignalType::Output
            }
            _ => unreachable!("parse_input_output_signal_decl called without Input/Output token"),
        };
        self.expect(&TokenKind::Signal)?;

        let tags = if self.eat(&TokenKind::LBrace) {
            let mut tags = Vec::new();
            if !self.at(&TokenKind::RBrace) {
                tags.push(self.expect_ident()?);
                while self.eat(&TokenKind::Comma) {
                    tags.push(self.expect_ident()?);
                }
            }
            self.expect(&TokenKind::RBrace)?;
            tags
        } else {
            Vec::new()
        };

        let mut declarations = Vec::new();
        declarations.push(self.parse_signal_name()?);
        while self.eat(&TokenKind::Comma) {
            declarations.push(self.parse_signal_name()?);
        }

        let init = match self.peek_kind() {
            TokenKind::ConstraintAssign => {
                self.advance();
                let expr = self.parse_expr()?;
                Some((AssignOp::ConstraintAssign, expr))
            }
            TokenKind::SignalAssign => {
                self.advance();
                let expr = self.parse_expr()?;
                Some((AssignOp::SignalAssign, expr))
            }
            _ => None,
        };

        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::SignalDecl {
            signal_type,
            tags,
            declarations,
            init,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_signal_name(&mut self) -> Result<SignalName, ParseError> {
        let sp = self.span();
        let name = self.expect_ident()?;
        let mut dimensions = Vec::new();
        while self.at(&TokenKind::LBracket) {
            self.advance();
            dimensions.push(self.parse_expr()?);
            self.expect(&TokenKind::RBracket)?;
        }
        Ok(SignalName {
            name,
            dimensions,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Variable declarations
    // ====================================================================

    /// `var name [= expr];` or `var (a, b) = expr;`
    pub(super) fn parse_var_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Var)?;

        // Tuple form: var (a, b, c) = expr;
        if self.eat(&TokenKind::LParen) {
            let mut names = Vec::new();
            names.push(self.expect_ident()?);
            while self.eat(&TokenKind::Comma) {
                names.push(self.expect_ident()?);
            }
            self.expect(&TokenKind::RParen)?;
            self.expect(&TokenKind::Assign)?;
            let init = self.parse_expr()?;
            self.expect(&TokenKind::Semicolon)?;
            return Ok(Stmt::VarDecl {
                names,
                dimensions: Vec::new(),
                init: Some(init),
                span: self.span_to_prev(&sp),
            });
        }

        let name = self.expect_ident()?;
        // Array dimensions for var. Preserved so the Artik witness
        // lift can allocate the backing buffer; the existing
        // scalar-var lowering paths ignore them safely.
        let mut dimensions = Vec::new();
        while self.at(&TokenKind::LBracket) {
            self.advance();
            dimensions.push(self.parse_expr()?);
            self.expect(&TokenKind::RBracket)?;
        }

        let init = if self.eat(&TokenKind::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };

        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::VarDecl {
            names: vec![name],
            dimensions,
            init,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Component declarations
    // ====================================================================

    /// `component name [= expr];` or `component name[size];`
    pub(super) fn parse_component_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Component)?;

        let mut names = Vec::new();
        names.push(self.parse_component_name()?);
        while self.eat(&TokenKind::Comma) {
            names.push(self.parse_component_name()?);
        }

        let init = if self.eat(&TokenKind::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };

        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::ComponentDecl {
            names,
            init,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_component_name(&mut self) -> Result<ComponentName, ParseError> {
        let sp = self.span();
        let name = self.expect_ident()?;
        let mut dimensions = Vec::new();
        while self.at(&TokenKind::LBracket) {
            self.advance();
            dimensions.push(self.parse_expr()?);
            self.expect(&TokenKind::RBracket)?;
        }
        Ok(ComponentName {
            name,
            dimensions,
            span: self.span_to_prev(&sp),
        })
    }
}
