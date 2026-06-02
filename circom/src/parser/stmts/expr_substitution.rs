use diagnostics::{ParseError, Span};

use crate::ast::*;
use crate::token::TokenKind;

use super::super::core::Parser;
use super::super::tables::tok_display;

impl Parser {
    // ====================================================================
    // Expression or substitution
    // ====================================================================

    /// Parse an expression, then check if it's followed by an assignment
    /// or constraint operator.
    pub(super) fn parse_expr_or_substitution(&mut self) -> Result<Stmt, ParseError> {
        let stmt = self.parse_expr_or_substitution_no_semi()?;
        self.expect(&TokenKind::Semicolon)?;
        Ok(stmt)
    }

    /// Same as above but without consuming the trailing semicolon.
    pub(super) fn parse_expr_or_substitution_no_semi(&mut self) -> Result<Stmt, ParseError> {
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
