use std::path::Path;

use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::declarations::DeclarationCompiler;
use crate::error::CompilerError;
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
}

/// Extract the source line number from a statement (1-based), or 0 if unavailable.
fn stmt_line(stmt: &Stmt) -> u32 {
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
        | Stmt::Export { span, .. } => span.line as u32,
        Stmt::Expr(expr) => expr_line(expr),
    }
}

/// Extract the source line number from an expression (1-based), or 0 if unavailable.
fn expr_line(expr: &Expr) -> u32 {
    expr.span().line as u32
}

impl StatementCompiler for Compiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError> {
        // Track source line for error reporting
        self.current().current_line = stmt_line(stmt);

        match stmt {
            Stmt::LetDecl { name, value, .. } => self.compile_let_decl(name, value),
            Stmt::MutDecl { name, value, .. } => self.compile_mut_decl(name, value),
            Stmt::Assignment { target, value, .. } => self.compile_assignment(target, value),
            Stmt::Print { value, .. } => {
                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1

                // 2. Load "print" (Pre-defined)
                let print_idx = *self
                    .global_symbols
                    .get("print")
                    .expect("Natives not initialized");
                self.emit_abx(OpCode::GetGlobal, func_reg, print_idx);

                // 3. Compile Argument
                self.compile_expr_into(value, arg_reg)?;

                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1);

                self.free_reg(arg_reg);
                self.free_reg(func_reg);
                Ok(())
            }
            Stmt::Break { .. } => self.compile_break(),
            Stmt::Continue { .. } => self.compile_continue(),
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    let reg = self.compile_expr(expr)?;
                    self.emit_abc(OpCode::Return, reg, 1, 0);
                    self.free_reg(reg);
                } else {
                    // Void return (0 values), do NOT load Nil
                    self.emit_abc(OpCode::Return, 0, 0, 0);
                }
                Ok(())
            }
            Stmt::FnDecl {
                name, params, body, ..
            } => {
                let reg = self.compile_fn_core(Some(name), params, body)?;
                self.free_reg(reg);
                Ok(())
            }
            Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => Ok(()), // no-op in VM
            Stmt::Import {
                path, alias, span, ..
            } => self.compile_import(path, alias, span),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::Expr(expr) => {
                let reg = self.compile_expr(expr)?;
                self.free_reg(reg);
                Ok(())
            }
        }
    }

    fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        _span: &Span,
    ) -> Result<(), CompilerError> {
        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            CompilerError::ModuleNotFound(format!(
                "module not found: {} (resolved from {})",
                path,
                base.display()
            ))
        })?;

        // 2. Check for duplicate alias
        if let Some(existing) = self.imported_aliases.get(alias) {
            if *existing != canonical {
                return Err(CompilerError::DuplicateModuleAlias(alias.to_string()));
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
            self.current().reg_top
        };

        for (i, name) in exported_names.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // Key: the export name as a string constant
            let key_handle = self.intern_string(name);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val);
            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants);
            }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16);

            // Value: load from the mangled global
            let mangled = format!("{}::{}", alias, name);
            let global_idx = *self.global_symbols.get(&mangled).ok_or_else(|| {
                CompilerError::CompileError(format!(
                    "internal error: mangled global `{}` not found after module compilation",
                    mangled
                ))
            })?;
            self.emit_abx(OpCode::GetGlobal, val_reg, global_idx);
        }

        self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8);

        // Free pair registers (LIFO: last allocated = first freed)
        if count > 0 {
            for _ in 0..(count * 2) {
                let top = self.current().reg_top - 1;
                self.free_reg(top);
            }
        }

        // Bind the map to the alias as a global
        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants);
        }
        let idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(alias.to_string(), idx);
        self.emit_abx(OpCode::DefGlobalLet, map_reg, idx);
        self.free_reg(map_reg);

        Ok(())
    }
}
