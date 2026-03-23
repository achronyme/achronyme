use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::types::Local;
use achronyme_parser::ast::*;
use achronyme_parser::Diagnostic;
use memory::Value;
use vm::opcode::OpCode;

pub trait DeclarationCompiler {
    fn compile_let_decl(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
    ) -> Result<(), CompilerError>;
    fn compile_mut_decl(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
    ) -> Result<(), CompilerError>;
    fn compile_assignment(&mut self, target: &Expr, value: &Expr) -> Result<(), CompilerError>;
}

impl DeclarationCompiler for Compiler {
    fn compile_let_decl(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
    ) -> Result<(), CompilerError> {
        let reg = self.compile_expr(value)?;

        check_type_annotation(self, name, type_ann, value);

        // Infer array type for let-bound array literals when no annotation is given.
        // Only for `let` (immutable) — `mut` arrays could be reassigned to different sizes.
        let effective_ann = match (type_ann, value) {
            (None, Expr::Array { elements, .. }) if !elements.is_empty() => {
                Some(TypeAnnotation::field_array(elements.len()))
            }
            _ => type_ann.cloned(),
        };

        if self.current()?.scope_depth > 0 {
            let depth = self.current()?.scope_depth;
            let span = self.current_span.clone();

            // Check for shadowing at same scope depth
            check_shadowing(self, name, depth, span.as_ref());

            self.current()?.locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                is_mutable: false,
                is_read: false,
                is_mutated: false,
                reg,
                span,
                type_ann: effective_ann,
            });
        } else {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants(self.cur_span()));
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;

            let global_name = match &self.module_prefix {
                Some(prefix) => format!("{prefix}::{name}"),
                None => name.to_string(),
            };
            self.global_symbols.insert(
                global_name,
                crate::types::GlobalEntry {
                    index: idx,
                    type_ann: effective_ann,
                    is_mutable: false,
                },
            );
            self.emit_abx(OpCode::DefGlobalLet, reg, idx)?;
            self.free_reg(reg)?;
        }
        Ok(())
    }

    fn compile_mut_decl(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
    ) -> Result<(), CompilerError> {
        let reg = self.compile_expr(value)?;

        check_type_annotation(self, name, type_ann, value);

        if self.current()?.scope_depth > 0 {
            let depth = self.current()?.scope_depth;
            let span = self.current_span.clone();

            // Check for shadowing at same scope depth
            check_shadowing(self, name, depth, span.as_ref());

            self.current()?.locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                is_mutable: true,
                is_read: false,
                is_mutated: false,
                reg,
                span,
                type_ann: type_ann.cloned(),
            });
        } else {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants(self.cur_span()));
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;

            let global_name = match &self.module_prefix {
                Some(prefix) => format!("{prefix}::{name}"),
                None => name.to_string(),
            };
            self.global_symbols.insert(
                global_name,
                crate::types::GlobalEntry {
                    index: idx,
                    type_ann: type_ann.cloned(),
                    is_mutable: true,
                },
            );
            self.emit_abx(OpCode::DefGlobalVar, reg, idx)?;
            self.free_reg(reg)?;
        }
        Ok(())
    }

    fn compile_assignment(&mut self, target: &Expr, value: &Expr) -> Result<(), CompilerError> {
        match target {
            Expr::Ident { name, .. } => {
                // Simple identifier assignment
                let val_reg = self.compile_expr(value)?;

                if let Some((idx, local_reg)) = self.resolve_local(name) {
                    self.current()?.locals[idx].is_mutated = true;
                    self.emit_abc(OpCode::Move, local_reg, val_reg, 0)?;
                } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name)
                {
                    self.mark_upvalue_mutated(self.compilers.len() - 1, name);
                    self.emit_abx(OpCode::SetUpvalue, val_reg, upval_idx as u16)?;
                } else if let Some(entry) = self.global_symbols.get(name) {
                    self.emit_abx(OpCode::SetGlobal, val_reg, entry.index)?;
                } else {
                    return Err(self.undefined_var_error(name));
                }

                self.free_reg(val_reg)?;
                Ok(())
            }
            Expr::Index { object, index, .. } => {
                // Indexed assignment: obj[key] = val
                let target_reg = self.compile_expr(object)?;
                let key_reg = self.compile_expr(index)?;
                let val_reg = self.compile_expr(value)?;

                self.emit_abc(OpCode::SetIndex, target_reg, key_reg, val_reg)?;

                self.free_reg(val_reg)?;
                self.free_reg(key_reg)?;
                self.free_reg(target_reg)?;
                Ok(())
            }
            Expr::DotAccess { object, field, .. } => {
                // Dot assignment: obj.field = val
                let target_reg = self.compile_expr(object)?;

                let handle = self.intern_string(field);
                let key_val = Value::string(handle);
                let const_idx = self.add_constant(key_val)?;
                let key_reg = self.alloc_reg()?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16)?;

                let val_reg = self.compile_expr(value)?;

                self.emit_abc(OpCode::SetIndex, target_reg, key_reg, val_reg)?;

                self.free_reg(val_reg)?;
                self.free_reg(key_reg)?;
                self.free_reg(target_reg)?;
                Ok(())
            }
            _ => Err(CompilerError::UnexpectedRule(
                "Invalid assignment target".into(),
                self.cur_span(),
            )),
        }
    }
}

// --- Type annotation checking (W006 / W007) ---

/// Statically inferred type from an AST literal expression.
enum InferredType {
    Field,
    Bool,
    Int,
    String,
    Nil,
    Array(usize),
}

impl std::fmt::Display for InferredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InferredType::Field => write!(f, "Field"),
            InferredType::Bool => write!(f, "Bool"),
            InferredType::Int => write!(f, "Int"),
            InferredType::String => write!(f, "String"),
            InferredType::Nil => write!(f, "Nil"),
            InferredType::Array(n) => write!(f, "Array[{n}]"),
        }
    }
}

/// Try to infer the type of a literal expression at compile time.
/// Returns `None` for dynamic expressions (calls, idents, binary ops, etc.).
fn infer_literal_type(expr: &Expr) -> Option<InferredType> {
    match expr {
        Expr::FieldLit { .. } => Some(InferredType::Field),
        Expr::Bool { .. } => Some(InferredType::Bool),
        Expr::Number { .. } => Some(InferredType::Int),
        Expr::StringLit { .. } => Some(InferredType::String),
        Expr::Nil { .. } => Some(InferredType::Nil),
        Expr::Array { elements, .. } => Some(InferredType::Array(elements.len())),
        _ => None,
    }
}

/// Check whether a type annotation is compatible with an inferred literal type.
fn is_ann_compatible(ann: &TypeAnnotation, inferred: &InferredType) -> bool {
    use achronyme_parser::ast::BaseType;
    match (&ann.base, ann.is_array(), inferred) {
        // Field accepts field literals and integers (int→field coercion)
        (BaseType::Field, false, InferredType::Field | InferredType::Int) => true,
        // Bool only accepts bool literals
        (BaseType::Bool, false, InferredType::Bool) => true,
        // Array annotations accept arrays (element types not checked at compile time)
        (_, true, InferredType::Array(_)) => true,
        _ => false,
    }
}

/// Extract expected array size from a type annotation, if it's an array type.
fn ann_array_size(ann: &TypeAnnotation) -> Option<usize> {
    ann.array_len()
}

/// Emit W006 (type mismatch) or W007 (array size mismatch) warnings when a type
/// annotation is present and the value's type can be statically inferred.
fn check_type_annotation(
    compiler: &mut Compiler,
    name: &str,
    type_ann: Option<&TypeAnnotation>,
    value: &Expr,
) {
    let (ann, inferred) = match (type_ann, infer_literal_type(value)) {
        (Some(a), Some(i)) => (a, i),
        _ => return,
    };

    let span = match &compiler.current_span {
        Some(s) => s.into(),
        None => return,
    };

    // W007: Array size mismatch (more specific, check first)
    if let (Some(expected), InferredType::Array(actual)) = (ann_array_size(ann), &inferred) {
        if expected != *actual {
            compiler.emit_warning(
                Diagnostic::warning(
                    format!("type `{ann}` expects {expected} elements, but array has {actual}",),
                    span,
                )
                .with_code("W007")
                .with_note("type annotations are checked at compile time in VM mode".to_string()),
            );
            return;
        }
    }

    // W006: Type mismatch
    if !is_ann_compatible(ann, &inferred) {
        compiler.emit_warning(
            Diagnostic::warning(
                format!(
                    "type annotation `{ann}` on `{name}` does not match value type `{inferred}`",
                ),
                span,
            )
            .with_code("W006")
            .with_note("type annotations are checked at compile time in VM mode".to_string()),
        );
    }
}

/// Emit a warning if a variable with the same name exists at the same scope depth.
fn check_shadowing(compiler: &mut Compiler, name: &str, depth: u32, span: Option<&Span>) {
    if name.starts_with('_') {
        return;
    }
    let shadowed = compiler.current_ref().ok().is_some_and(|func| {
        func.locals
            .iter()
            .any(|l| l.name == name && l.depth == depth)
    });
    if shadowed {
        if let Some(s) = span {
            compiler.emit_warning(
                Diagnostic::warning(
                    format!("variable `{name}` shadows a previous binding in the same scope"),
                    s.into(),
                )
                .with_code("W004"),
            );
        }
    }
}
