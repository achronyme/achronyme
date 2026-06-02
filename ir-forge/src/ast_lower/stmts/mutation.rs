use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(in crate::ast_lower) fn compile_mut_decl(
        &mut self,
        name: &str,
        _type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array literal → mutable LetArray
        if let Expr::Array {
            elements,
            span: arr_span,
            ..
        } = value
        {
            if elements.is_empty() {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "empty arrays are not allowed in circuits".into(),
                    span: to_span(arr_span),
                });
            }
            let compiled: Result<Vec<_>, _> =
                elements.iter().map(|e| self.compile_expr(e)).collect();
            let compiled = compiled?;
            let elem_names: Vec<String> =
                (0..compiled.len()).map(|i| format!("{name}_{i}")).collect();
            self.body.push(CircuitNode::LetArray {
                name: name.to_string(),
                elements: compiled,
                span: Some(SpanRange::from(span)),
            });
            for ename in &elem_names {
                self.env
                    .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
            }
            self.env
                .insert(name.to_string(), CompEnvValue::Array(elem_names));
            // Mark as mutable so arr[i] = expr is allowed
            self.ssa_versions.insert(name.to_string(), 0);
            return Ok(());
        }

        // Type annotations intentionally ignored (see compile_let).
        // Compile value and emit Let node (same as immutable let for v0)
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: name.to_string(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });
        // Register in env as the current name (v0 uses the original name)
        self.env
            .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
        // Mark as mutable with version 0
        self.ssa_versions.insert(name.to_string(), 0);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Assignment (desugared to SSA rebinding)
    // -----------------------------------------------------------------------

    pub(in crate::ast_lower) fn compile_assignment(
        &mut self,
        target: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array element assignment: arr[i] = expr → LetIndexed
        if let Expr::Index {
            object,
            index,
            span: idx_span,
            ..
        } = target
        {
            return self.compile_indexed_assignment(object, index, value, idx_span);
        }

        // Simple ident assignment: x = expr
        let name = match target {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "only simple variable or array element assignment \
                         is supported in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check that the variable was declared with mut
        let version = self.ssa_versions.get(&name).copied().ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{name}` — it was not declared with `mut` \
                     (use `mut {name} = ...` to declare a mutable variable)"
                ),
                span: to_span(span),
            }
        })?;

        // Increment version (checked to avoid panic on theoretical overflow)
        let new_version =
            version
                .checked_add(1)
                .ok_or_else(|| ProveIrError::UnsupportedOperation {
                    description: format!(
                        "SSA version overflow for `{name}` — too many reassignments"
                    ),
                    span: to_span(span),
                })?;
        self.ssa_versions.insert(name.clone(), new_version);

        // Generate SSA name using $ separator (not valid in user identifiers).
        let ssa_name = format!("{name}$v{new_version}");

        // Compile the new value
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: ssa_name.clone(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });

        // Update env to point to the new SSA name
        self.env.insert(name, CompEnvValue::Scalar(ssa_name));
        Ok(())
    }

    /// Compile `arr[i] = expr` → `LetIndexed { array, index, value }`.
    pub(in crate::ast_lower) fn compile_indexed_assignment(
        &mut self,
        object: &Expr,
        index: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let array_name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexed assignment requires an array identifier \
                         (e.g., arr[i] = expr)"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists and is an array
        if !matches!(
            self.env.get(array_name.as_str()),
            Some(CompEnvValue::Array(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "mutable array".into(),
                got: "scalar or undeclared".into(),
                span: to_span(span),
            });
        }

        // Check the array was declared with mut
        if !self.ssa_versions.contains_key(&array_name) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{array_name}[..]` — array was not declared with `mut` \
                     (use `mut {array_name} = [...]` to declare a mutable array)"
                ),
                span: to_span(span),
            });
        }

        let compiled_index = self.compile_expr(index)?;
        let compiled_value = self.compile_expr(value)?;

        self.body.push(CircuitNode::LetIndexed {
            array: array_name,
            index: compiled_index,
            value: compiled_value,
            span: Some(SpanRange::from(span)),
        });

        Ok(())
    }
}
