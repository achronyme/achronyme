mod declarations;
mod import_export;
mod misc;
mod types;

use crate::ast::*;
use crate::error::ParseError;
use crate::token::TokenKind;

use super::core::Parser;

impl Parser {
    // ========================================================================
    // Statements
    // ========================================================================

    pub(super) fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek_kind() {
            TokenKind::Import => self.parse_import(),
            TokenKind::Export => self.parse_export(),
            TokenKind::Let => self.parse_let_decl(),
            TokenKind::Mut => self.parse_mut_decl(),
            TokenKind::Public => self.parse_public_decl(),
            TokenKind::Witness => self.parse_witness_decl(),
            TokenKind::Fn => {
                // fn as statement requires a name (fn_decl)
                // fn as expression may or may not have a name
                // Disambiguate: `fn <ident> (` -> FnDecl statement
                if matches!(self.lookahead(1), TokenKind::Ident)
                    && matches!(self.lookahead(2), TokenKind::LParen)
                {
                    self.parse_fn_decl()
                } else {
                    // fn expression (anonymous or named used as value)
                    let expr = self.parse_expr()?;
                    self.try_parse_assignment(expr)
                }
            }
            TokenKind::Print => self.parse_print(),
            TokenKind::Return => self.parse_return(),
            TokenKind::Break => {
                let sp = self.span();
                self.advance();
                Ok(Stmt::Break {
                    span: self.span_to_prev(&sp),
                })
            }
            TokenKind::Continue => {
                let sp = self.span();
                self.advance();
                Ok(Stmt::Continue {
                    span: self.span_to_prev(&sp),
                })
            }
            TokenKind::Circuit => self.parse_circuit_decl(),
            TokenKind::Prove
                // prove name(...) { ... } -> desugar to let name = prove name(...) { ... }
                // prove(...) { ... } or prove { ... } -> expression statement
                if matches!(self.lookahead(1), TokenKind::Ident)
                    && matches!(self.lookahead(2), TokenKind::LParen | TokenKind::LBrace)
                => {
                    self.parse_prove_decl()
                }
            _ => {
                let expr = self.parse_expr()?;
                self.try_parse_assignment(expr)
            }
        }
    }

    /// After parsing an expression, check if `=` follows to make it an assignment.
    fn try_parse_assignment(&mut self, expr: Expr) -> Result<Stmt, ParseError> {
        if self.at(&TokenKind::Assign) {
            let sp = expr.span().clone();
            self.advance();
            let value = self.parse_expr()?;
            Ok(Stmt::Assignment {
                target: expr,
                value,
                span: self.span_to_prev(&sp),
            })
        } else {
            Ok(Stmt::Expr(expr))
        }
    }
}
