//! Top-level statement dispatch.
//!
//! Defines the [`StatementCompiler`] trait and its single `impl for Compiler`.
//! The heart is [`StatementCompiler::compile_stmt`] — a match over
//! [`Stmt`] that routes each variant to its specialized compiler
//! (declarations, control flow, circuit/circom imports, etc.).
//!
//! Statement-specific logic lives in sibling submodules:
//! - `circuit.rs` — `circuit { … }` and `import circuit`
//! - `imports.rs` — `import` and selective `import { … } from`
//! - `declarations.rs` — let/mut
//! - `circom_imports.rs` — `.circom` dispatch targets

use super::{circuit, imports};
use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::declarations::DeclarationCompiler;
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;
use crate::functions::FunctionDefinitionCompiler;
use achronyme_parser::ast::*;
use vm::opcode::OpCode;

pub trait StatementCompiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError>;
    fn compile_import(&mut self, path: &str, alias: &str, span: &Span)
        -> Result<(), CompilerError>;
    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), CompilerError>;
    fn compile_circuit_decl(
        &mut self,
        name: &str,
        params: &[TypedParam],
        body: &Block,
        span: &Span,
    ) -> Result<(), CompilerError>;
    fn compile_import_circuit(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError>;
}

/// Extract the source line number from a statement (1-based), or 0 if unavailable.
fn stmt_line(stmt: &Stmt) -> u32 {
    stmt_span(stmt).map_or(0, |s| s.line_start as u32)
}

/// Extract the span from a statement, if available.
pub(crate) fn stmt_span(stmt: &Stmt) -> Option<&Span> {
    match stmt {
        Stmt::LetDecl { span, .. }
        | Stmt::MutDecl { span, .. }
        | Stmt::Assignment { span, .. }
        | Stmt::Print { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::FnDecl { span, .. }
        | Stmt::PublicDecl { span, .. }
        | Stmt::WitnessDecl { span, .. }
        | Stmt::Break { span }
        | Stmt::Continue { span }
        | Stmt::Import { span, .. }
        | Stmt::Export { span, .. }
        | Stmt::SelectiveImport { span, .. }
        | Stmt::ExportList { span, .. }
        | Stmt::CircuitDecl { span, .. }
        | Stmt::ImportCircuit { span, .. }
        | Stmt::Error { span } => Some(span),
        Stmt::Expr(expr) => Some(expr.span()),
    }
}

impl StatementCompiler for Compiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError> {
        // Track source line for error reporting
        self.current()?.current_line = stmt_line(stmt);
        // Track span for error diagnostics
        self.current_span = stmt_span(stmt).cloned();

        match stmt {
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                ..
            } => self.compile_let_decl(name, type_ann.as_ref(), value),
            Stmt::MutDecl {
                name,
                type_ann,
                value,
                ..
            } => self.compile_mut_decl(name, type_ann.as_ref(), value),
            Stmt::Assignment { target, value, .. } => self.compile_assignment(target, value),
            Stmt::Print { value, .. } => {
                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1

                // 2. Load "print" (Pre-defined)
                let print_idx = self
                    .global_symbols
                    .get("print")
                    .ok_or_else(|| {
                        CompilerError::InternalError(
                            "native function 'print' not registered".into(),
                        )
                    })?
                    .index;
                self.emit_abx(OpCode::GetGlobal, func_reg, print_idx)?;

                // 3. Compile Argument
                self.compile_expr_into(value, arg_reg)?;

                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1)?;

                self.free_reg(arg_reg)?;
                self.free_reg(func_reg)?;
                Ok(())
            }
            Stmt::Break { .. } => self.compile_break(),
            Stmt::Continue { .. } => self.compile_continue(),
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    let reg = self.compile_expr(expr)?;
                    self.emit_abc(OpCode::Return, reg, 1, 0)?;
                    self.free_reg(reg)?;
                } else {
                    // Void return (0 values), do NOT load Nil
                    self.emit_abc(OpCode::Return, 0, 0, 0)?;
                }
                Ok(())
            }
            Stmt::FnDecl {
                name, params, body, ..
            } => {
                // Store the AST for ProveIR (prove/circuit blocks inline outer functions).
                // Only capture top-level functions (depth 1 = main script scope).
                //
                // When we're inside a namespace-imported module
                // (`module_prefix = Some(alias)`), tag the stored FnDecl
                // with its qualified name `alias::name` so prove blocks
                // that dispatch via the `::` path find it in their
                // `fn_table`. Without this, `h::commitment(...)` inside a
                // prove block would silently miss because the module's
                // functions land in the outer scope's fn_decl_asts with
                // their bare name and the ProveIR compiler keys
                // `fn_table` by the literal FnDecl name.
                if self.compilers.len() == 1 {
                    if let Some(prefix) = self.module_prefix.clone() {
                        let qualified = format!("{prefix}::{name}");
                        // Rebuild the stmt with the qualified name. Only
                        // `FnDecl.name` changes; params, body,
                        // return_type, span all stay put.
                        let tagged = if let Stmt::FnDecl {
                            params,
                            body,
                            return_type,
                            span,
                            ..
                        } = stmt
                        {
                            Stmt::FnDecl {
                                name: qualified,
                                params: params.clone(),
                                body: body.clone(),
                                return_type: return_type.clone(),
                                span: span.clone(),
                            }
                        } else {
                            unreachable!("outer match arm guarantees Stmt::FnDecl")
                        };
                        self.fn_decl_asts.push(tagged);
                    } else {
                        self.fn_decl_asts.push(stmt.clone());
                    }
                }
                // Phase 4: skip VM bytecode for ProveIr-only functions.
                // Their AST is already captured in fn_decl_asts above
                // for ProveIR inlining; the VM compiler has no use for them.
                let fn_key = match &self.module_prefix {
                    Some(prefix) => format!("{prefix}::{name}"),
                    None => name.clone(),
                };
                if let Some(map) = &self.resolver_availability_map {
                    if let Some(avail) = map.get(&fn_key) {
                        if !avail.includes_vm() {
                            return Ok(());
                        }
                    }
                }

                let reg = self.compile_fn_core(Some(name), params, body)?;
                self.free_reg(reg)?;
                Ok(())
            }
            Stmt::PublicDecl { span, .. } | Stmt::WitnessDecl { span, .. } => {
                Err(CompilerError::CompileError(
                    "top-level `public`/`witness` declarations are not supported; \
                     use `circuit name(param: Public, ...) { body }` instead"
                        .into(),
                    span_box(span),
                ))
            }
            Stmt::Import {
                path, alias, span, ..
            } => self.compile_import(path, alias, span),
            Stmt::SelectiveImport {
                names, path, span, ..
            } => self.compile_selective_import(names, path, span),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::ExportList { .. } => {
                // Export lists are metadata — handled by collect_exports, no bytecode to emit
                Ok(())
            }
            Stmt::CircuitDecl {
                name,
                params,
                body,
                span,
            } => self.compile_circuit_decl(name, params, body, span),
            Stmt::ImportCircuit {
                path, alias, span, ..
            } => self.compile_import_circuit(path, alias, span),
            Stmt::Error { .. } => Ok(()),
            Stmt::Expr(expr) => {
                let reg = self.compile_expr(expr)?;
                self.free_reg(reg)?;
                Ok(())
            }
        }
    }

    fn compile_circuit_decl(
        &mut self,
        name: &str,
        params: &[TypedParam],
        body: &Block,
        span: &Span,
    ) -> Result<(), CompilerError> {
        circuit::compile_circuit_decl(self, name, params, body, span)
    }

    fn compile_import_circuit(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        circuit::compile_import_circuit(self, path, alias, span)
    }

    fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        imports::compile_import(self, path, alias, span)
    }

    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        imports::compile_selective_import(self, names, path, span)
    }
}
