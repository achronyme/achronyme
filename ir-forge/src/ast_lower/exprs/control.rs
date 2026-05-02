//! Control-flow expression compilation.
//!
//! Three methods that lower branching, indexing, and block expressions:
//!
//! - `compile_if_expr` — emits a `CircuitNode::If` for branch bodies
//!   and a `CircuitExpr::Mux` for the result value.
//! - `compile_index` — array element access; folds constant indices,
//!   defers dynamic ones to `CircuitExpr::ArrayIndex`.
//! - `compile_block_as_expr` — runs statement-level compilation over a
//!   block and returns its trailing expression as the result.

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn compile_if_expr(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let cond = self.compile_expr(condition)?;

        // Bind condition to a temporary to avoid duplicating it in both
        // the CircuitNode::If and the Mux (which would double constraint cost).
        let cond_var = format!("$cond{}", self.inline_counter);
        self.inline_counter = self.inline_counter.wrapping_add(1);
        self.body.push(CircuitNode::Let {
            name: cond_var.clone(),
            value: cond,
            span: Some(SpanRange::from(span)),
        });
        let cond_ref = CircuitExpr::Var(cond_var);

        // Save body vec, compile then/else into separate buffers
        let saved_body = std::mem::take(&mut self.body);

        // Then branch
        self.body = Vec::new();
        let then_result = self.compile_block_as_expr(then_block)?;
        let then_nodes = std::mem::take(&mut self.body);

        // Else branch
        self.body = Vec::new();
        let (else_result, else_nodes) = match else_branch {
            Some(ElseBranch::Block(block)) => {
                let r = self.compile_block_as_expr(block)?;
                (r, std::mem::take(&mut self.body))
            }
            Some(ElseBranch::If(if_expr)) => {
                let r = self.compile_expr(if_expr)?;
                (r, std::mem::take(&mut self.body))
            }
            None => (CircuitExpr::Const(FieldConst::zero()), Vec::new()),
        };

        // Restore body and emit the If node
        self.body = saved_body;

        // If both branches have side-effect nodes (Let, Assert, etc.),
        // emit them as a CircuitNode::If. The result values become
        // the Mux during instantiation (Phase B).
        if !then_nodes.is_empty() || !else_nodes.is_empty() {
            self.body.push(CircuitNode::If {
                cond: cond_ref.clone(),
                then_body: then_nodes,
                else_body: else_nodes,
                span: Some(SpanRange::from(span)),
            });
        }

        // The expression result is a Mux over the two branch results
        Ok(CircuitExpr::Mux {
            cond: Box::new(cond_ref),
            if_true: Box::new(then_result),
            if_false: Box::new(else_result),
        })
    }

    pub(super) fn compile_index(
        &mut self,
        object: &Expr,
        index: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexing is only supported on array identifiers in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists
        if !matches!(
            self.env.get(name.as_str()),
            Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: to_span(span),
            });
        }

        // Try to resolve as a constant index → direct element access
        if let Expr::Number { value, .. } = index {
            if let Ok(idx) = value.parse::<usize>() {
                if let Some(CompEnvValue::Array(elems)) = self.env.get(name.as_str()) {
                    if idx >= elems.len() {
                        return Err(ProveIrError::IndexOutOfBounds {
                            name: name.clone(),
                            index: idx,
                            length: elems.len(),
                            span: to_span(span),
                        });
                    }
                    return Ok(CircuitExpr::Var(elems[idx].clone()));
                }
            }
        }

        // Dynamic or capture-based index → ArrayIndex node
        let idx_expr = self.compile_expr(index)?;
        Ok(CircuitExpr::ArrayIndex {
            array: name,
            index: Box::new(idx_expr),
        })
    }

    /// Compile a block of statements and return the result of the last expression.
    /// Intermediate statements (Let, AssertEq, etc.) are appended to self.body.
    /// The last expression statement becomes the return value.
    /// If the block has no expression result, returns Const(ZERO).
    pub(super) fn compile_block_as_expr(
        &mut self,
        block: &Block,
    ) -> Result<CircuitExpr, ProveIrError> {
        let stmts = &block.stmts;
        if stmts.is_empty() {
            return Ok(CircuitExpr::Const(FieldConst::zero()));
        }

        // Compile all but the last statement normally
        for stmt in &stmts[..stmts.len() - 1] {
            // Handle Return inside function body
            if let Stmt::Return { value, .. } = stmt {
                return match value {
                    Some(expr) => self.compile_expr(expr),
                    None => Ok(CircuitExpr::Const(FieldConst::zero())),
                };
            }
            self.compile_stmt(stmt)?;
        }

        // The last statement: if it's an Expr, return its value; otherwise compile and return ZERO
        let last = &stmts[stmts.len() - 1];
        match last {
            Stmt::Expr(expr) => self.compile_expr(expr),
            Stmt::Return { value, .. } => match value {
                Some(expr) => self.compile_expr(expr),
                None => Ok(CircuitExpr::Const(FieldConst::zero())),
            },
            other => {
                self.compile_stmt(other)?;
                Ok(CircuitExpr::Const(FieldConst::zero()))
            }
        }
    }
}
