use diagnostics::{ParseError, Span};

use crate::ast::*;
use crate::token::TokenKind;

use super::core::Parser;
use super::tables::tok_display;

// ========================================================================
// Binding power table
// ========================================================================

/// Returns `(left_bp, right_bp)` for infix binary operators.
/// Left-associative: right_bp = left_bp + 1
/// Right-associative: right_bp = left_bp
fn infix_bp(kind: &TokenKind) -> Option<(u8, u8)> {
    match kind {
        // Logical OR — lowest precedence
        TokenKind::Or => Some((1, 2)),
        // Logical AND
        TokenKind::And => Some((3, 4)),
        // Equality / comparison
        TokenKind::Eq | TokenKind::Neq => Some((5, 6)),
        TokenKind::Lt | TokenKind::Le | TokenKind::Gt | TokenKind::Ge => Some((7, 8)),
        // Bitwise OR
        TokenKind::BitOr => Some((9, 10)),
        // Bitwise XOR
        TokenKind::BitXor => Some((11, 12)),
        // Bitwise AND
        TokenKind::BitAnd => Some((13, 14)),
        // Bit shifts
        TokenKind::ShiftL | TokenKind::ShiftR => Some((15, 16)),
        // Addition / subtraction
        TokenKind::Plus | TokenKind::Minus => Some((17, 18)),
        // Multiplication / division / modulo / int-div
        TokenKind::Star | TokenKind::Slash | TokenKind::IntDiv | TokenKind::Percent => {
            Some((19, 20))
        }
        // Exponentiation (left-associative in Circom, unlike math convention)
        TokenKind::Power => Some((21, 22)),
        _ => None,
    }
}

/// Prefix binding power.
const PREFIX_BP: u8 = 23;

/// Postfix binding power (call, index, dot, ++, --).
const POSTFIX_BP: u8 = 25;

fn token_to_binop(kind: &TokenKind) -> BinOp {
    match kind {
        TokenKind::Plus => BinOp::Add,
        TokenKind::Minus => BinOp::Sub,
        TokenKind::Star => BinOp::Mul,
        TokenKind::Slash => BinOp::Div,
        TokenKind::IntDiv => BinOp::IntDiv,
        TokenKind::Percent => BinOp::Mod,
        TokenKind::Power => BinOp::Pow,
        TokenKind::Eq => BinOp::Eq,
        TokenKind::Neq => BinOp::Neq,
        TokenKind::Lt => BinOp::Lt,
        TokenKind::Le => BinOp::Le,
        TokenKind::Gt => BinOp::Gt,
        TokenKind::Ge => BinOp::Ge,
        TokenKind::And => BinOp::And,
        TokenKind::Or => BinOp::Or,
        TokenKind::BitAnd => BinOp::BitAnd,
        TokenKind::BitOr => BinOp::BitOr,
        TokenKind::BitXor => BinOp::BitXor,
        TokenKind::ShiftL => BinOp::ShiftL,
        TokenKind::ShiftR => BinOp::ShiftR,
        _ => unreachable!("token_to_binop called with non-binop token"),
    }
}

// ========================================================================
// Expression parsing
// ========================================================================

impl Parser {
    /// Public entry point for expression parsing.
    pub(super) fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_bp(0)
    }

    /// Pratt parser: parse expressions with binding power >= min_bp.
    fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_prefix()?;

        loop {
            // Ternary: `expr ? expr : expr` (lowest precedence, right-assoc)
            if self.at(&TokenKind::Question) && min_bp == 0 {
                self.advance();
                let if_true = self.parse_expr_bp(0)?;
                self.expect(&TokenKind::Colon)?;
                let if_false = self.parse_expr_bp(0)?;
                let span = Span::from_to(lhs.span(), if_false.span());
                lhs = Expr::Ternary {
                    condition: Box::new(lhs),
                    if_true: Box::new(if_true),
                    if_false: Box::new(if_false),
                    span,
                };
                continue;
            }

            // Postfix operators (highest precedence)
            match self.peek_kind() {
                TokenKind::LParen if POSTFIX_BP >= min_bp => {
                    lhs = self.parse_call_or_anon_component(lhs)?;
                    continue;
                }
                TokenKind::LBracket if POSTFIX_BP >= min_bp => {
                    lhs = self.parse_index(lhs)?;
                    continue;
                }
                TokenKind::Dot if POSTFIX_BP >= min_bp => {
                    lhs = self.parse_dot_access(lhs)?;
                    continue;
                }
                TokenKind::Increment if POSTFIX_BP >= min_bp => {
                    let sp = self.span();
                    self.advance();
                    let span = Span::from_to(lhs.span(), &sp);
                    lhs = Expr::PostfixOp {
                        op: PostfixOp::Increment,
                        operand: Box::new(lhs),
                        span,
                    };
                    continue;
                }
                TokenKind::Decrement if POSTFIX_BP >= min_bp => {
                    let sp = self.span();
                    self.advance();
                    let span = Span::from_to(lhs.span(), &sp);
                    lhs = Expr::PostfixOp {
                        op: PostfixOp::Decrement,
                        operand: Box::new(lhs),
                        span,
                    };
                    continue;
                }
                _ => {}
            }

            // Infix binary operators
            if let Some((l_bp, r_bp)) = infix_bp(self.peek_kind()) {
                if l_bp < min_bp {
                    break;
                }
                let op_kind = self.peek_kind().clone();
                self.advance();
                let rhs = self.parse_expr_bp(r_bp)?;
                let span = Span::from_to(lhs.span(), rhs.span());
                lhs = Expr::BinOp {
                    op: token_to_binop(&op_kind),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span,
                };
                continue;
            }

            break;
        }

        Ok(lhs)
    }

    // ====================================================================
    // Prefix parsing
    // ====================================================================

    fn parse_prefix(&mut self) -> Result<Expr, ParseError> {
        match self.peek_kind() {
            // Unary operators
            TokenKind::Minus => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr_bp(PREFIX_BP)?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::UnaryOp {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                    span,
                })
            }
            TokenKind::Not => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr_bp(PREFIX_BP)?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::UnaryOp {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                    span,
                })
            }
            TokenKind::BitNot => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr_bp(PREFIX_BP)?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::UnaryOp {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                    span,
                })
            }
            // Prefix increment/decrement: ++i, --i
            TokenKind::Increment => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr_bp(PREFIX_BP)?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::PrefixOp {
                    op: PostfixOp::Increment,
                    operand: Box::new(operand),
                    span,
                })
            }
            TokenKind::Decrement => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr_bp(PREFIX_BP)?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::PrefixOp {
                    op: PostfixOp::Decrement,
                    operand: Box::new(operand),
                    span,
                })
            }
            // `parallel expr`
            TokenKind::Parallel => {
                let sp = self.span();
                self.advance();
                let operand = self.parse_expr()?;
                let span = Span::from_to(&sp, operand.span());
                Ok(Expr::ParallelOp {
                    operand: Box::new(operand),
                    span,
                })
            }
            // Atoms
            _ => self.parse_atom(),
        }
    }

    // ====================================================================
    // Atoms
    // ====================================================================

    fn parse_atom(&mut self) -> Result<Expr, ParseError> {
        let tok = self.peek();
        match tok.kind {
            TokenKind::DecNumber => {
                let value = tok.lexeme.clone();
                let span = tok.span.clone();
                self.advance();
                Ok(Expr::Number { value, span })
            }
            TokenKind::HexNumber => {
                let value = tok.lexeme.clone();
                let span = tok.span.clone();
                self.advance();
                Ok(Expr::HexNumber { value, span })
            }
            TokenKind::Ident => {
                let name = tok.lexeme.clone();
                let span = tok.span.clone();
                self.advance();
                Ok(Expr::Ident { name, span })
            }
            TokenKind::Underscore => {
                let span = tok.span.clone();
                self.advance();
                Ok(Expr::Underscore { span })
            }
            // Parenthesized expression or tuple
            TokenKind::LParen => self.parse_paren_or_tuple(),
            // Array literal
            TokenKind::LBracket => self.parse_array_lit(),
            _ => Err(ParseError::new(
                format!("expected expression, found {}", tok_display(tok)),
                tok.span.line_start,
                tok.span.col_start,
            )),
        }
    }

    fn parse_paren_or_tuple(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::LParen)?;

        if self.at(&TokenKind::RParen) {
            self.advance();
            return Ok(Expr::Tuple {
                elements: Vec::new(),
                span: self.span_to_prev(&sp),
            });
        }

        let first = self.parse_expr()?;

        if self.eat(&TokenKind::Comma) {
            // Tuple: (a, b, ...)
            let mut elements = vec![first];
            if !self.at(&TokenKind::RParen) {
                elements.push(self.parse_expr()?);
                while self.eat(&TokenKind::Comma) {
                    elements.push(self.parse_expr()?);
                }
            }
            self.expect(&TokenKind::RParen)?;
            Ok(Expr::Tuple {
                elements,
                span: self.span_to_prev(&sp),
            })
        } else {
            // Parenthesized expression
            self.expect(&TokenKind::RParen)?;
            Ok(first)
        }
    }

    fn parse_array_lit(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::LBracket)?;
        let elements = self.parse_expr_list()?;
        self.expect(&TokenKind::RBracket)?;
        Ok(Expr::ArrayLit {
            elements,
            span: self.span_to_prev(&sp),
        })
    }

    // ====================================================================
    // Postfix operations
    // ====================================================================

    /// Parse `callee(args)` or anonymous component `Template(params)(inputs)`.
    fn parse_call_or_anon_component(&mut self, callee: Expr) -> Result<Expr, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let args = self.parse_expr_list()?;
        self.expect(&TokenKind::RParen)?;
        let call_span = Span::from_to(callee.span(), &self.prev_span());

        // Check for anonymous component: immediately followed by another `(`
        if self.at(&TokenKind::LParen) {
            self.expect(&TokenKind::LParen)?;
            let signal_args = self.parse_anon_signal_args()?;
            self.expect(&TokenKind::RParen)?;
            let span = Span::from_to(callee.span(), &self.prev_span());
            return Ok(Expr::AnonComponent {
                callee: Box::new(callee),
                template_args: args,
                signal_args,
                span,
            });
        }

        Ok(Expr::Call {
            callee: Box::new(callee),
            args,
            span: call_span,
        })
    }

    fn parse_anon_signal_args(&mut self) -> Result<Vec<AnonSignalArg>, ParseError> {
        let mut args = Vec::new();
        if !self.at(&TokenKind::RParen) {
            args.push(self.parse_anon_signal_arg()?);
            while self.eat(&TokenKind::Comma) {
                args.push(self.parse_anon_signal_arg()?);
            }
        }
        Ok(args)
    }

    fn parse_anon_signal_arg(&mut self) -> Result<AnonSignalArg, ParseError> {
        // Named: `input_name <== expr`
        if self.peek_kind() == &TokenKind::Ident
            && self.lookahead(1) == &TokenKind::ConstraintAssign
        {
            let name = self.expect_ident()?;
            self.expect(&TokenKind::ConstraintAssign)?;
            let value = self.parse_expr()?;
            return Ok(AnonSignalArg {
                name: Some(name),
                value,
            });
        }
        // Positional
        let value = self.parse_expr()?;
        Ok(AnonSignalArg { name: None, value })
    }

    fn parse_index(&mut self, object: Expr) -> Result<Expr, ParseError> {
        self.expect(&TokenKind::LBracket)?;
        let index = self.parse_expr()?;
        self.expect(&TokenKind::RBracket)?;
        let span = Span::from_to(object.span(), &self.prev_span());
        Ok(Expr::Index {
            object: Box::new(object),
            index: Box::new(index),
            span,
        })
    }

    fn parse_dot_access(&mut self, object: Expr) -> Result<Expr, ParseError> {
        self.expect(&TokenKind::Dot)?;
        let field = self.expect_ident()?;
        let span = Span::from_to(object.span(), &self.prev_span());
        Ok(Expr::DotAccess {
            object: Box::new(object),
            field,
            span,
        })
    }
}
