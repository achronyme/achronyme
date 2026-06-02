use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::ProveIrCompiler;
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(in crate::ast_lower) fn compile_expr_stmt(
        &mut self,
        expr: &Expr,
    ) -> Result<(), ProveIrError> {
        // Detect assert_eq(a, b) and assert(x) to emit constraint nodes
        if let Expr::Call {
            callee, args, span, ..
        } = expr
        {
            let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
            if let Expr::Ident { name, .. } = callee.as_ref() {
                match name.as_str() {
                    "assert_eq" => {
                        self.check_assert_eq_arity(arg_vals.len(), span)?;
                        let lhs = self.compile_expr(arg_vals[0])?;
                        let rhs = self.compile_expr(arg_vals[1])?;
                        let message = self.extract_assert_message(arg_vals.get(2), span)?;
                        self.body.push(CircuitNode::AssertEq {
                            lhs,
                            rhs,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    "assert" => {
                        self.check_assert_arity(arg_vals.len(), span)?;
                        let cond = self.compile_expr(arg_vals[0])?;
                        let message = self.extract_assert_message(arg_vals.get(1), span)?;
                        self.body.push(CircuitNode::Assert {
                            expr: cond,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // General expression statement
        let compiled = self.compile_expr(expr)?;
        self.body.push(CircuitNode::Expr {
            expr: compiled,
            span: Some(SpanRange::from(expr.span())),
        });
        Ok(())
    }
}
