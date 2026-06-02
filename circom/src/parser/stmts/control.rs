use diagnostics::ParseError;

use crate::ast::*;
use crate::token::TokenKind;

use super::super::core::Parser;

impl Parser {
    // ====================================================================
    // Control flow
    // ====================================================================

    /// Parse a block `{ stmts }` or a single bare statement.
    ///
    /// Circom allows both `for (...) { body }` and `for (...) stmt;`.
    fn parse_block_or_stmt(&mut self) -> Result<Block, ParseError> {
        if self.at(&TokenKind::LBrace) {
            self.parse_block()
        } else {
            let sp = self.span();
            let stmt = self.parse_stmt()?;
            Ok(Block {
                stmts: vec![stmt],
                span: self.span_to_prev(&sp),
            })
        }
    }

    pub(super) fn parse_if_else(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::If)?;
        self.expect(&TokenKind::LParen)?;
        let condition = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;

        let then_body = self.parse_block_or_stmt()?;

        let else_body = if self.eat(&TokenKind::Else) {
            if self.at(&TokenKind::If) {
                Some(ElseBranch::IfElse(Box::new(self.parse_if_else()?)))
            } else {
                Some(ElseBranch::Block(self.parse_block_or_stmt()?))
            }
        } else {
            None
        };

        Ok(Stmt::IfElse {
            condition,
            then_body,
            else_body,
            span: self.span_to_prev(&sp),
        })
    }

    /// `for (init; cond; step) { body }` or `for (init; cond; step) stmt;`
    pub(super) fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::For)?;
        self.expect(&TokenKind::LParen)?;

        // Init: either var decl or substitution (without trailing semicolon)
        let init = self.parse_for_init()?;
        // Condition
        let condition = self.parse_expr()?;
        self.expect(&TokenKind::Semicolon)?;
        // Step
        let step = self.parse_for_step()?;

        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block_or_stmt()?;

        Ok(Stmt::For {
            init: Box::new(init),
            condition,
            step: Box::new(step),
            body,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_for_init(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        if self.at(&TokenKind::Var) {
            self.expect(&TokenKind::Var)?;
            let name = self.expect_ident()?;
            let init = if self.eat(&TokenKind::Assign) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.expect(&TokenKind::Semicolon)?;
            Ok(Stmt::VarDecl {
                names: vec![name],
                dimensions: Vec::new(),
                init,
                span: self.span_to_prev(&sp),
            })
        } else {
            let stmt = self.parse_expr_or_substitution_no_semi()?;
            self.expect(&TokenKind::Semicolon)?;
            Ok(stmt)
        }
    }

    fn parse_for_step(&mut self) -> Result<Stmt, ParseError> {
        self.parse_expr_or_substitution_no_semi()
    }

    pub(super) fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::While)?;
        self.expect(&TokenKind::LParen)?;
        let condition = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block_or_stmt()?;

        Ok(Stmt::While {
            condition,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    /// `do { body } while (cond);`
    pub(super) fn parse_do_while(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Do)?;
        let body = self.parse_block_or_stmt()?;
        self.expect(&TokenKind::While)?;
        self.expect(&TokenKind::LParen)?;
        let condition = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::DoWhile {
            body,
            condition,
            span: self.span_to_prev(&sp),
        })
    }
}
