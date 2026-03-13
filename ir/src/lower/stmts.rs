use achronyme_parser::ast::*;

use crate::error::IrError;
use crate::types::{Instruction, IrType, SsaVar};

use super::{annotation_to_ir_type, to_ir_span, type_compatible, EnvValue, FnDef, IrLowering};

impl IrLowering {
    pub(super) fn lower_program(&mut self, program: &Program) -> Result<(), IrError> {
        for stmt in &program.stmts {
            self.lower_stmt(stmt)?;
        }
        Ok(())
    }

    pub(super) fn lower_stmt(&mut self, stmt: &Stmt) -> Result<Option<SsaVar>, IrError> {
        match stmt {
            Stmt::PublicDecl { names, .. } => {
                self.lower_public_decl(names)?;
                Ok(None)
            }
            Stmt::WitnessDecl { names, .. } => {
                self.lower_witness_decl(names)?;
                Ok(None)
            }
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => {
                self.lower_let(name, type_ann.as_ref(), value, span)?;
                Ok(None)
            }
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
                    },
                );
                Ok(None)
            }
            Stmt::Expr(expr) => {
                let v = self.lower_expr(expr)?;
                Ok(Some(v))
            }
            Stmt::MutDecl { span, .. } => Err(IrError::UnsupportedOperation(
                "mutable variables are not supported in circuits (circuit variables are immutable — use 'let' instead)".into(),
                to_ir_span(span),
            )),
            Stmt::Print { span, .. } => Err(IrError::UnsupportedOperation(
                "print is not supported in circuits (circuits produce constraints, not output — use the VM for debugging)".into(),
                to_ir_span(span),
            )),
            Stmt::Assignment { span, .. } => Err(IrError::UnsupportedOperation(
                "assignment is not supported in circuits (circuit variables are write-once — use a new 'let' binding instead)".into(),
                to_ir_span(span),
            )),
            Stmt::Break { span } => Err(IrError::UnsupportedOperation(
                "break is not supported in circuits (loops must have statically-known bounds for unrolling)".into(),
                to_ir_span(span),
            )),
            Stmt::Continue { span } => Err(IrError::UnsupportedOperation(
                "continue is not supported in circuits (loops must have statically-known bounds for unrolling)".into(),
                to_ir_span(span),
            )),
            Stmt::Return { span, .. } => Err(IrError::UnsupportedOperation(
                "return is not supported in circuits (circuits are flat constraint systems — use the final expression as the result)".into(),
                to_ir_span(span),
            )),
            Stmt::Import {
                path, alias, span, ..
            } => {
                self.load_module(path, alias, span)?;
                Ok(None)
            }
            Stmt::SelectiveImport {
                names, path, span, ..
            } => {
                self.load_module_selective(names, path, span)?;
                Ok(None)
            }
            Stmt::Export { inner, .. } => self.lower_stmt(inner),
            Stmt::ExportList { .. } => {
                // Export lists are metadata — handled by collect_exports, no IR to emit
                Ok(None)
            }
            Stmt::Error { .. } => Ok(None),
        }
    }

    fn lower_public_decl(&mut self, names: &[InputDecl]) -> Result<(), IrError> {
        for decl in names {
            if let Some(size) = decl.array_size {
                let vars = self.declare_public_array(&decl.name, size);
                if let Some(ref ann) = decl.type_ann {
                    self.enforce_input_type_ann(ann, &vars);
                }
            } else {
                let v = self.declare_public(&decl.name);
                if let Some(ref ann) = decl.type_ann {
                    self.enforce_input_type_ann(ann, &[v]);
                }
            }
        }
        Ok(())
    }

    fn lower_witness_decl(&mut self, names: &[InputDecl]) -> Result<(), IrError> {
        for decl in names {
            if let Some(size) = decl.array_size {
                let vars = self.declare_witness_array(&decl.name, size);
                if let Some(ref ann) = decl.type_ann {
                    self.enforce_input_type_ann(ann, &vars);
                }
            } else {
                let v = self.declare_witness(&decl.name);
                if let Some(ref ann) = decl.type_ann {
                    self.enforce_input_type_ann(ann, &[v]);
                }
            }
        }
        Ok(())
    }

    /// Apply a type annotation to input variables, emitting `RangeCheck(v, 1)` for
    /// `: Bool` annotations. Input variables are always untyped at declaration time,
    /// so Bool enforcement is always needed for soundness.
    pub(super) fn enforce_input_type_ann(&mut self, ann: &TypeAnnotation, vars: &[SsaVar]) {
        let ty = annotation_to_ir_type(ann);
        if ty == IrType::Bool {
            for &v in vars {
                let enforced = self.program.fresh_var();
                self.program.push(Instruction::RangeCheck {
                    result: enforced,
                    operand: v,
                    bits: 1,
                });
                self.program.set_type(enforced, IrType::Bool);
                // Also stamp the original so env lookups see the type
                self.program.set_type(v, IrType::Bool);
            }
        } else {
            for &v in vars {
                self.program.set_type(v, ty);
            }
        }
    }

    pub(super) fn lower_let(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), IrError> {
        // Check if RHS is an array literal
        if let Expr::Array {
            elements,
            span: arr_span,
        } = value
        {
            let sp = to_ir_span(arr_span);
            if elements.is_empty() {
                return Err(IrError::UnsupportedOperation(
                    "empty arrays are not allowed in circuits".into(),
                    sp,
                ));
            }
            let mut vars = elements
                .iter()
                .map(|e| self.lower_expr(e))
                .collect::<Result<Vec<_>, _>>()?;
            // Validate and enforce types from annotation if provided
            if let Some(ann) = type_ann {
                // Reject scalar annotations on array values
                if matches!(ann, TypeAnnotation::Field | TypeAnnotation::Bool) {
                    return Err(IrError::TypeMismatch {
                        expected: format!("{}[{}]", ann, vars.len()),
                        got: format!("{ann}"),
                        span: to_ir_span(span),
                    });
                }
                // Validate array size matches annotation
                let expected_size = match ann {
                    TypeAnnotation::FieldArray(n) | TypeAnnotation::BoolArray(n) => Some(*n),
                    _ => None,
                };
                if let Some(expected) = expected_size {
                    if vars.len() != expected {
                        return Err(IrError::ArrayLengthMismatch {
                            expected,
                            got: vars.len(),
                            span: to_ir_span(arr_span),
                        });
                    }
                }
                let elem_ty = annotation_to_ir_type(ann);
                if elem_ty == IrType::Bool {
                    // For Bool arrays, enforce each element
                    for (i, v) in vars.iter_mut().enumerate() {
                        if let Some(inferred) = self.program.get_type(*v) {
                            if !type_compatible(elem_ty, inferred) {
                                return Err(IrError::AnnotationMismatch {
                                    name: format!("{name}[{i}]"),
                                    declared: elem_ty.to_string(),
                                    inferred: inferred.to_string(),
                                    span: to_ir_span(arr_span),
                                });
                            }
                            // Already typed and compatible (e.g., Bool) — keep as-is
                        } else {
                            // Untyped element — emit RangeCheck for enforcement
                            let enforced = self.program.fresh_var();
                            self.program.push(Instruction::RangeCheck {
                                result: enforced,
                                operand: *v,
                                bits: 1,
                            });
                            self.program.set_type(enforced, IrType::Bool);
                            *v = enforced;
                        }
                    }
                } else {
                    // Field[N]: only stamp if element doesn't already have a
                    // more specific type (Bool is subtype of Field).
                    for v in &vars {
                        if self.program.get_type(*v) != Some(IrType::Bool) {
                            self.program.set_type(*v, elem_ty);
                        }
                    }
                }
            }
            self.env.insert(name.to_string(), EnvValue::Array(vars));
            return Ok(());
        }

        let v = self.lower_expr(value)?;

        // Validate type annotation if present
        let bound_var = if let Some(ann) = type_ann {
            // Reject array annotations on scalar values
            if matches!(
                ann,
                TypeAnnotation::FieldArray(_) | TypeAnnotation::BoolArray(_)
            ) {
                return Err(IrError::TypeMismatch {
                    expected: "scalar".into(),
                    got: format!("{ann}"),
                    span: to_ir_span(span),
                });
            }
            let declared = annotation_to_ir_type(ann);
            if let Some(inferred) = self.program.get_type(v) {
                if !type_compatible(declared, inferred) {
                    return Err(IrError::AnnotationMismatch {
                        name: name.to_string(),
                        declared: declared.to_string(),
                        inferred: inferred.to_string(),
                        span: to_ir_span(span),
                    });
                }
                // Already typed and compatible — use as-is
                self.program.set_type(v, declared);
                v
            } else if declared == IrType::Bool {
                // Untyped value annotated as Bool — emit RangeCheck(v, 1) for enforcement
                let enforced = self.program.fresh_var();
                self.program.push(Instruction::RangeCheck {
                    result: enforced,
                    operand: v,
                    bits: 1,
                });
                self.program.set_type(enforced, IrType::Bool);
                enforced
            } else {
                // Field annotation on untyped — safe, no enforcement needed
                self.program.set_type(v, declared);
                v
            }
        } else {
            v
        };

        // `let` is an alias — no instruction emitted, just env binding
        self.program.set_name(bound_var, name.to_string());
        self.env
            .insert(name.to_string(), EnvValue::Scalar(bound_var));
        Ok(())
    }
}
