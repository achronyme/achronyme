use diagnostics::{ParseError, Span};

use crate::ast::*;
use crate::token::TokenKind;

use super::core::Parser;
use super::tables::tok_display;

impl Parser {
    /// Parse a single statement.
    pub(super) fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek_kind() {
            TokenKind::Signal => self.parse_signal_decl(),
            TokenKind::Input | TokenKind::Output => self.parse_signal_decl_reversed(),
            TokenKind::Var => self.parse_var_decl(),
            TokenKind::Component => self.parse_component_decl(),
            TokenKind::If => self.parse_if_else(),
            TokenKind::For => self.parse_for(),
            TokenKind::While => self.parse_while(),
            TokenKind::Do => self.parse_do_while(),
            TokenKind::Return => self.parse_return(),
            TokenKind::Assert => self.parse_assert(),
            TokenKind::Log => self.parse_log(),
            TokenKind::LBrace => Ok(Stmt::Block(self.parse_block()?)),
            _ => self.parse_expr_or_substitution(),
        }
    }

    // ====================================================================
    // Signal declarations
    // ====================================================================

    /// `signal [input|output] [{tags}] name[dims]... [<== expr | <-- expr];`
    fn parse_signal_decl(&mut self) -> Result<Stmt, ParseError> {
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
    fn parse_signal_decl_reversed(&mut self) -> Result<Stmt, ParseError> {
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
    fn parse_var_decl(&mut self) -> Result<Stmt, ParseError> {
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
                init: Some(init),
                span: self.span_to_prev(&sp),
            });
        }

        let name = self.expect_ident()?;
        // Array dimensions for var
        while self.at(&TokenKind::LBracket) {
            self.advance();
            let _size = self.parse_expr()?;
            self.expect(&TokenKind::RBracket)?;
            // Note: var array dimensions don't affect name list,
            // they're just initialization
        }

        let init = if self.eat(&TokenKind::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };

        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::VarDecl {
            names: vec![name],
            init,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Component declarations
    // ====================================================================

    /// `component name [= expr];` or `component name[size];`
    fn parse_component_decl(&mut self) -> Result<Stmt, ParseError> {
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

    fn parse_if_else(&mut self) -> Result<Stmt, ParseError> {
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
    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
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

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
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
    fn parse_do_while(&mut self) -> Result<Stmt, ParseError> {
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

    fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Return)?;
        let value = self.parse_expr()?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(Stmt::Return {
            value,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_assert(&mut self) -> Result<Stmt, ParseError> {
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

    fn parse_log(&mut self) -> Result<Stmt, ParseError> {
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

    // ====================================================================
    // Expression or substitution
    // ====================================================================

    /// Parse an expression, then check if it's followed by an assignment
    /// or constraint operator.
    fn parse_expr_or_substitution(&mut self) -> Result<Stmt, ParseError> {
        let stmt = self.parse_expr_or_substitution_no_semi()?;
        self.expect(&TokenKind::Semicolon)?;
        Ok(stmt)
    }

    /// Same as above but without consuming the trailing semicolon.
    fn parse_expr_or_substitution_no_semi(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();

        // Handle tuple substitution: (a, b) <== expr
        if self.at(&TokenKind::LParen) {
            // Could be tuple assignment or parenthesized expression
            // Try tuple: (ident, ident, ...) followed by assignment op
            if self.is_tuple_target() {
                return self.parse_tuple_substitution(&sp);
            }
        }

        // Handle underscore: _ <== expr
        if self.at(&TokenKind::Underscore) {
            let usp = self.span();
            self.advance();
            let target = Expr::Underscore { span: usp };
            if let Some(op) = self.try_parse_assign_op() {
                let value = self.parse_expr()?;
                return Ok(Stmt::Substitution {
                    target,
                    op,
                    value,
                    span: self.span_to_prev(&sp),
                });
            }
            return Ok(Stmt::Expr {
                expr: target,
                span: self.span_to_prev(&sp),
            });
        }

        let lhs = self.parse_expr()?;

        // Check for assignment / constraint operators
        if let Some(op) = self.try_parse_assign_op() {
            let value = self.parse_expr()?;
            return Ok(Stmt::Substitution {
                target: lhs,
                op,
                value,
                span: self.span_to_prev(&sp),
            });
        }

        // Check for constraint equality: ===
        if self.eat(&TokenKind::ConstraintEq) {
            let rhs = self.parse_expr()?;
            return Ok(Stmt::ConstraintEq {
                lhs,
                rhs,
                span: self.span_to_prev(&sp),
            });
        }

        // Check for compound assignment
        if let Some(cop) = self.try_parse_compound_op() {
            let value = self.parse_expr()?;
            return Ok(Stmt::CompoundAssign {
                target: lhs,
                op: cop,
                value,
                span: self.span_to_prev(&sp),
            });
        }

        // Bare expression (e.g., i++, function call)
        Ok(Stmt::Expr {
            expr: lhs,
            span: self.span_to_prev(&sp),
        })
    }

    fn try_parse_assign_op(&mut self) -> Option<AssignOp> {
        let op = match self.peek_kind() {
            TokenKind::Assign => AssignOp::Assign,
            TokenKind::ConstraintAssign => AssignOp::ConstraintAssign,
            TokenKind::SignalAssign => AssignOp::SignalAssign,
            TokenKind::RConstraintAssign => AssignOp::RConstraintAssign,
            TokenKind::RSignalAssign => AssignOp::RSignalAssign,
            _ => return None,
        };
        self.advance();
        Some(op)
    }

    fn try_parse_compound_op(&mut self) -> Option<CompoundOp> {
        let op = match self.peek_kind() {
            TokenKind::PlusAssign => CompoundOp::Add,
            TokenKind::MinusAssign => CompoundOp::Sub,
            TokenKind::StarAssign => CompoundOp::Mul,
            TokenKind::SlashAssign => CompoundOp::Div,
            TokenKind::IntDivAssign => CompoundOp::IntDiv,
            TokenKind::PercentAssign => CompoundOp::Mod,
            TokenKind::PowerAssign => CompoundOp::Pow,
            TokenKind::ShiftLAssign => CompoundOp::ShiftL,
            TokenKind::ShiftRAssign => CompoundOp::ShiftR,
            TokenKind::BitAndAssign => CompoundOp::BitAnd,
            TokenKind::BitOrAssign => CompoundOp::BitOr,
            TokenKind::BitXorAssign => CompoundOp::BitXor,
            _ => return None,
        };
        self.advance();
        Some(op)
    }

    /// Check if we're at a tuple target: `(ident, ident, ...) op`
    fn is_tuple_target(&self) -> bool {
        // Quick heuristic: (ident followed by , or ))
        if self.lookahead(0) != &TokenKind::LParen {
            return false;
        }
        let mut i = 1;
        loop {
            match self.lookahead(i) {
                TokenKind::Ident | TokenKind::Underscore => {
                    i += 1;
                    match self.lookahead(i) {
                        TokenKind::Comma => i += 1,
                        TokenKind::RParen => {
                            i += 1;
                            // Must be followed by an assignment op
                            return matches!(
                                self.lookahead(i),
                                TokenKind::ConstraintAssign
                                    | TokenKind::SignalAssign
                                    | TokenKind::Assign
                                    | TokenKind::RConstraintAssign
                                    | TokenKind::RSignalAssign
                            );
                        }
                        _ => return false,
                    }
                }
                _ => return false,
            }
        }
    }

    fn parse_tuple_substitution(&mut self, sp: &Span) -> Result<Stmt, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let mut elements = Vec::new();
        loop {
            if self.at(&TokenKind::Underscore) {
                let usp = self.span();
                self.advance();
                elements.push(Expr::Underscore { span: usp });
            } else {
                let isp = self.span();
                let name = self.expect_ident()?;
                elements.push(Expr::Ident {
                    name,
                    span: self.span_to_prev(&isp),
                });
            }
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RParen)?;

        let op = self.try_parse_assign_op().ok_or_else(|| {
            let tok = self.peek();
            ParseError::with_code(
                format!(
                    "expected assignment operator after tuple, found {}",
                    tok_display(tok)
                ),
                "E300",
                tok.span.line_start,
                tok.span.col_start,
            )
        })?;

        let value = self.parse_expr()?;
        let tuple_span = self.span_to_prev(sp);
        let target = Expr::Tuple {
            elements,
            span: tuple_span.clone(),
        };

        Ok(Stmt::Substitution {
            target,
            op,
            value,
            span: tuple_span,
        })
    }
}
