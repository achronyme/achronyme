use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::{FnDef, ProveIrCompiler};
use crate::error::ProveIrError;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Compile all statements in a block, appending to self.body.
    pub(in crate::ast_lower) fn compile_block_stmts(
        &mut self,
        block: &Block,
    ) -> Result<(), ProveIrError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    /// Compile a single statement.
    pub(in crate::ast_lower) fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), ProveIrError> {
        match stmt {
            Stmt::PublicDecl { names, span } => self.compile_public_decl(names, span),
            Stmt::WitnessDecl { names, span } => self.compile_witness_decl(names, span),
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_let(name, type_ann.as_ref(), value, span),
            Stmt::FnDecl {
                name,
                params,
                return_type,
                body,
                ..
            } => {
                self.fn_table.insert(
                    name.clone(),
                    FnDef {
                        params: params.clone(),
                        body: body.clone(),
                        return_type: return_type.clone(),
                        owner_module: None,
                        availability: None,
                    },
                );
                Ok(())
            }
            Stmt::Expr(expr) => self.compile_expr_stmt(expr),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::ExportList { .. } | Stmt::Error { .. } => Ok(()),

            Stmt::MutDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_mut_decl(name, type_ann.as_ref(), value, span),
            Stmt::Assignment {
                target,
                value,
                span,
            } => self.compile_assignment(target, value, span),
            Stmt::Print { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "print is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Break { span } => Err(ProveIrError::UnsupportedOperation {
                description: "break is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Continue { span } => Err(ProveIrError::UnsupportedOperation {
                description: "continue is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Return { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "return is not supported at the top level of a circuit".into(),
                span: to_span(span),
            }),
            Stmt::Import { path, alias, span } => self.compile_import(path, alias, span),
            Stmt::SelectiveImport { names, path, span } => {
                self.compile_selective_import(names, path, span)
            }
            Stmt::CircuitDecl { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit declarations are not supported inside circuits".into(),
                span: to_span(span),
            }),
            Stmt::ImportCircuit { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit imports are not supported inside circuits".into(),
                span: to_span(span),
            }),
        }
    }
}
