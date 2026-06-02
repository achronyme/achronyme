use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::helpers::{annotation_to_ir_type, to_span};
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;
use ir_core::IrType;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(in crate::ast_lower) fn compile_public_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, true)
    }

    pub(in crate::ast_lower) fn compile_witness_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, false)
    }

    /// Shared implementation for public/witness input declarations.
    pub(in crate::ast_lower) fn compile_input_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
        is_public: bool,
    ) -> Result<(), ProveIrError> {
        for decl in names {
            // Check for duplicate declarations across both public and witness inputs.
            // We check the input lists directly (not self.env) because env also
            // contains captures from the outer scope, which are legitimately
            // "overridden" by an explicit public/witness declaration.
            let already_declared = self
                .public_inputs
                .iter()
                .chain(self.witness_inputs.iter())
                .any(|d| d.name == decl.name);
            if already_declared {
                return Err(ProveIrError::DuplicateInput {
                    name: decl.name.clone(),
                    span: to_span(span),
                });
            }

            let ir_type = match decl.type_ann.as_ref() {
                Some(ann) => annotation_to_ir_type(ann, span)?,
                None => IrType::Field,
            };

            let inputs = if is_public {
                &mut self.public_inputs
            } else {
                &mut self.witness_inputs
            };

            if let Some(size) = decl.array_size {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: Some(ArraySize::Literal(size)),
                    ir_type,
                });
                let elem_names: Vec<String> =
                    (0..size).map(|i| format!("{}_{i}", decl.name)).collect();
                for ename in &elem_names {
                    self.env
                        .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                }
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Array(elem_names));
            } else {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: None,
                    ir_type,
                });
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Scalar(decl.name.clone()));
            }
        }
        Ok(())
    }
}
