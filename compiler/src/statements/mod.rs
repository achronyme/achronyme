use std::path::Path;

use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::declarations::DeclarationCompiler;
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;
use crate::functions::FunctionDefinitionCompiler;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub mod declarations;

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
                let print_idx = *self.global_symbols.get("print").ok_or_else(|| {
                    CompilerError::InternalError("native function 'print' not registered".into())
                })?;
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
                let reg = self.compile_fn_core(Some(name), params, body)?;
                self.free_reg(reg)?;
                Ok(())
            }
            Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => Ok(()), // no-op in VM
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
        // 1. Synthesize public/witness declarations from circuit params
        let mut stmts = Vec::new();
        for param in params {
            let visibility = param
                .type_ann
                .as_ref()
                .and_then(|ann| ann.visibility)
                .unwrap_or(Visibility::Witness);
            let decl = InputDecl {
                name: param.name.clone(),
                type_ann: param.type_ann.clone(),
            };
            match visibility {
                Visibility::Public => stmts.push(Stmt::PublicDecl {
                    names: vec![decl],
                    span: span.clone(),
                }),
                Visibility::Witness => stmts.push(Stmt::WitnessDecl {
                    names: vec![decl],
                    span: span.clone(),
                }),
            }
        }
        stmts.extend(body.stmts.clone());
        let circuit_body = Block {
            stmts,
            span: body.span.clone(),
        };

        // 2. Compile to ProveIR (no outer scope — circuit is self-contained)
        let mut prove_ir = ir::prove_ir::ProveIrCompiler::compile(
            &circuit_body,
            &std::collections::HashMap::new(),
        )
        .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
        prove_ir.name = Some(name.to_string());

        // 3. Serialize to bytes
        let ir_bytes = prove_ir.to_bytes().map_err(|e| {
            CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
        })?;

        // 4. Store bytes in constant pool and bind as global
        let handle = self.intern_bytes(ir_bytes);
        let val = Value::bytes(handle);
        let idx = self.add_constant(val)?;
        if idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }

        // Bind the circuit name as a global pointing to the bytes constant
        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let global_idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(name.to_string(), global_idx);

        // Emit: load the bytes constant into a register, then define as global
        let reg = self.alloc_reg()?;
        self.emit_abx(vm::opcode::OpCode::LoadConst, reg, idx as u16)?;
        self.emit_abx(vm::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
        self.free_reg(reg)?;

        Ok(())
    }

    fn compile_import_circuit(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let full_path = base.join(path);

        if !full_path.exists() {
            return Err(CompilerError::CompileError(
                format!("circuit file not found: {}", full_path.display()),
                span_box(span),
            ));
        }

        // 2. Read circuit source
        let source = std::fs::read_to_string(&full_path).map_err(|e| {
            CompilerError::CompileError(
                format!("cannot read circuit file {}: {e}", full_path.display()),
                span_box(span),
            )
        })?;

        // 3. Compile to ProveIR via compile_circuit (self-contained)
        let mut prove_ir = ir::prove_ir::ProveIrCompiler::compile_circuit(&source)
            .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
        prove_ir.name = Some(alias.to_string());

        // 4. Serialize to bytes
        let ir_bytes = prove_ir.to_bytes().map_err(|e| {
            CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
        })?;

        // 5. Store bytes in constant pool and bind alias as global
        let handle = self.intern_bytes(ir_bytes);
        let val = Value::bytes(handle);
        let idx = self.add_constant(val)?;
        if idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }

        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let global_idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(alias.to_string(), global_idx);

        let reg = self.alloc_reg()?;
        self.emit_abx(vm::opcode::OpCode::LoadConst, reg, idx as u16)?;
        self.emit_abx(vm::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
        self.free_reg(reg)?;

        Ok(())
    }

    fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            CompilerError::ModuleNotFound(
                format!(
                    "module not found: {} (resolved from {})",
                    path,
                    base.display()
                ),
                span_box(span),
            )
        })?;

        // 2. Check for duplicate alias
        if let Some(existing) = self.imported_aliases.get(alias) {
            if *existing != canonical {
                return Err(CompilerError::DuplicateModuleAlias(
                    alias.to_string(),
                    span_box(span),
                ));
            }
            // Same path, same alias → already imported, skip
            return Ok(());
        }
        self.imported_aliases
            .insert(alias.to_string(), canonical.clone());

        // 3. Check for circular imports
        if self.compiling_modules.contains(&canonical) {
            return Err(CompilerError::CircularImport(
                canonical.display().to_string(),
                span_box(span),
            ));
        }

        // 4. Load and parse the module
        let module = self.module_loader.load(&canonical)?;
        let module_stmts = module.program.stmts.clone();
        let exported_names = module.exported_names.clone();

        // 5. Mark as compiling (for cycle detection during stmt compilation)
        self.compiling_modules.insert(canonical.clone());

        // 6. Save and set module_prefix + base_path for name mangling
        let old_prefix = self.module_prefix.take();
        let old_base = self.base_path.take();
        self.module_prefix = Some(alias.to_string());
        self.base_path = canonical.parent().map(|p| p.to_path_buf());

        // 7. Compile the module's statements (globals get mangled as alias::name)
        for stmt in &module_stmts {
            self.compile_stmt(stmt)?;
        }

        // 8. Restore prefix and base_path, remove from compiling set
        self.module_prefix = old_prefix;
        self.base_path = old_base;
        self.compiling_modules.remove(&canonical);

        // 9. Build a Map { export_name: value } and bind it to the alias
        let count = exported_names.len();

        // Allocate target register first (LIFO register hygiene)
        let map_reg = self.alloc_reg()?;

        let start_reg = if count > 0 {
            self.alloc_contiguous((count * 2) as u8)?
        } else {
            self.current()?.reg_top
        };

        for (i, name) in exported_names.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // Key: the export name as a string constant
            let key_handle = self.intern_string(name);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val)?;
            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants(span_box(span)));
            }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16)?;

            // Value: load from the mangled global
            let mangled = format!("{}::{}", alias, name);
            let global_idx = *self.global_symbols.get(&mangled).ok_or_else(|| {
                CompilerError::CompileError(
                    format!(
                        "internal error: mangled global `{}` not found after module compilation",
                        mangled
                    ),
                    span_box(span),
                )
            })?;
            self.emit_abx(OpCode::GetGlobal, val_reg, global_idx)?;
        }

        self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

        // Free pair registers (LIFO: last allocated = first freed)
        if count > 0 {
            for _ in 0..(count * 2) {
                let top = self.current()?.reg_top - 1;
                self.free_reg(top)?;
            }
        }

        // Bind the map to the alias as a global
        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(alias.to_string(), idx);
        self.emit_abx(OpCode::DefGlobalLet, map_reg, idx)?;
        self.free_reg(map_reg)?;

        Ok(())
    }

    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            CompilerError::ModuleNotFound(
                format!(
                    "module not found: {} (resolved from {})",
                    path,
                    base.display()
                ),
                span_box(span),
            )
        })?;

        // 2. Check for circular imports
        if self.compiling_modules.contains(&canonical) {
            return Err(CompilerError::CircularImport(
                canonical.display().to_string(),
                span_box(span),
            ));
        }

        // 3. Load and parse the module
        let module = self.module_loader.load(&canonical)?;
        let module_stmts = module.program.stmts.clone();
        let exported_names = module.exported_names.clone();

        // 4. Validate that all requested names are exported
        for name in names {
            if !exported_names.contains(name) {
                let suggestion = crate::suggest::find_similar(
                    name,
                    exported_names.iter().map(|s| s.as_str()),
                    2,
                );
                let mut msg = format!("module \"{}\" does not export `{}`", path, name);
                if let Some(s) = suggestion {
                    msg.push_str(&format!(". Did you mean `{s}`?"));
                }
                return Err(CompilerError::CompileError(msg, span_box(span)));
            }
        }

        // 5. Check for conflicts with existing names
        for name in names {
            if let Some((existing_path, _)) = self.imported_names.get(name) {
                if *existing_path != canonical {
                    return Err(CompilerError::CompileError(
                        format!(
                            "`{}` already imported from \"{}\"",
                            name,
                            existing_path.display()
                        ),
                        span_box(span),
                    ));
                }
                // Same name from same module — already imported, skip
                continue;
            }
            if self.global_symbols.contains_key(name) {
                return Err(CompilerError::CompileError(
                    format!(
                        "cannot import `{}`: a global with this name already exists",
                        name
                    ),
                    span_box(span),
                ));
            }
        }

        // 6. Generate internal module prefix
        let internal_prefix = format!("__sel_{}", self.imported_aliases.len());

        // 7. Mark as compiling (for cycle detection)
        self.compiling_modules.insert(canonical.clone());

        // 8. Save and set module_prefix + base_path for name mangling
        let old_prefix = self.module_prefix.take();
        let old_base = self.base_path.take();
        self.module_prefix = Some(internal_prefix.clone());
        self.base_path = canonical.parent().map(|p| p.to_path_buf());

        // 9. Compile the module's statements
        for stmt in &module_stmts {
            self.compile_stmt(stmt)?;
        }

        // 10. Restore prefix and base_path, remove from compiling set
        self.module_prefix = old_prefix;
        self.base_path = old_base;
        self.compiling_modules.remove(&canonical);

        // 11. Copy only the requested names from mangled globals to user-visible globals
        for name in names {
            if self.imported_names.contains_key(name) {
                // Already imported from same module — skip
                continue;
            }

            let mangled = format!("{}::{}", internal_prefix, name);
            let global_idx = *self.global_symbols.get(&mangled).ok_or_else(|| {
                CompilerError::CompileError(
                    format!(
                        "internal error: mangled global `{}` not found after module compilation",
                        mangled
                    ),
                    span_box(span),
                )
            })?;

            // Emit GetGlobal + DefGlobalLet to copy value to a new global slot
            let tmp_reg = self.alloc_reg()?;
            self.emit_abx(OpCode::GetGlobal, tmp_reg, global_idx)?;

            if self.next_global_idx == u16::MAX {
                self.free_reg(tmp_reg)?;
                return Err(CompilerError::TooManyConstants(span_box(span)));
            }
            let new_idx = self.next_global_idx;
            self.next_global_idx += 1;
            self.global_symbols.insert(name.clone(), new_idx);
            self.emit_abx(OpCode::DefGlobalLet, tmp_reg, new_idx)?;
            self.free_reg(tmp_reg)?;

            self.imported_names
                .insert(name.clone(), (canonical.clone(), span.clone()));
        }

        Ok(())
    }
}
