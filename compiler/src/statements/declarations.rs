use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::types::Local;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub trait DeclarationCompiler {
    fn compile_let_decl(&mut self, name: &str, value: &Expr) -> Result<(), CompilerError>;
    fn compile_mut_decl(&mut self, name: &str, value: &Expr) -> Result<(), CompilerError>;
    fn compile_assignment(&mut self, target: &Expr, value: &Expr) -> Result<(), CompilerError>;
}

impl DeclarationCompiler for Compiler {
    fn compile_let_decl(&mut self, name: &str, value: &Expr) -> Result<(), CompilerError> {
        let reg = self.compile_expr(value)?;

        if self.current().scope_depth > 0 {
            let depth = self.current().scope_depth;
            self.current().locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                reg,
            });
        } else {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;

            let global_name = match &self.module_prefix {
                Some(prefix) => format!("{prefix}::{name}"),
                None => name.to_string(),
            };
            self.global_symbols.insert(global_name, idx);
            self.emit_abx(OpCode::DefGlobalLet, reg, idx);
            self.free_reg(reg);
        }
        Ok(())
    }

    fn compile_mut_decl(&mut self, name: &str, value: &Expr) -> Result<(), CompilerError> {
        let reg = self.compile_expr(value)?;

        if self.current().scope_depth > 0 {
            let depth = self.current().scope_depth;
            self.current().locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                reg,
            });
        } else {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;

            let global_name = match &self.module_prefix {
                Some(prefix) => format!("{prefix}::{name}"),
                None => name.to_string(),
            };
            self.global_symbols.insert(global_name, idx);
            self.emit_abx(OpCode::DefGlobalVar, reg, idx);
            self.free_reg(reg);
        }
        Ok(())
    }

    fn compile_assignment(&mut self, target: &Expr, value: &Expr) -> Result<(), CompilerError> {
        match target {
            Expr::Ident { name, .. } => {
                // Simple identifier assignment
                let val_reg = self.compile_expr(value)?;

                if let Some((_, local_reg)) = self.resolve_local(name) {
                    self.emit_abc(OpCode::Move, local_reg, val_reg, 0);
                } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name)
                {
                    self.emit_abx(OpCode::SetUpvalue, val_reg, upval_idx as u16);
                } else if let Some(global_idx) = self.global_symbols.get(name) {
                    self.emit_abx(OpCode::SetGlobal, val_reg, *global_idx);
                } else {
                    return Err(CompilerError::UnknownOperator(format!(
                        "Undefined variable '{}'",
                        name
                    )));
                }

                self.free_reg(val_reg);
                Ok(())
            }
            Expr::Index { object, index, .. } => {
                // Indexed assignment: obj[key] = val
                let target_reg = self.compile_expr(object)?;
                let key_reg = self.compile_expr(index)?;
                let val_reg = self.compile_expr(value)?;

                self.emit_abc(OpCode::SetIndex, target_reg, key_reg, val_reg);

                self.free_reg(val_reg);
                self.free_reg(key_reg);
                self.free_reg(target_reg);
                Ok(())
            }
            Expr::DotAccess { object, field, .. } => {
                // Dot assignment: obj.field = val
                let target_reg = self.compile_expr(object)?;

                let handle = self.intern_string(field);
                let key_val = Value::string(handle);
                let const_idx = self.add_constant(key_val);
                let key_reg = self.alloc_reg()?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants);
                }
                self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16);

                let val_reg = self.compile_expr(value)?;

                self.emit_abc(OpCode::SetIndex, target_reg, key_reg, val_reg);

                self.free_reg(val_reg);
                self.free_reg(key_reg);
                self.free_reg(target_reg);
                Ok(())
            }
            _ => Err(CompilerError::UnexpectedRule(
                "Invalid assignment target".into(),
            )),
        }
    }
}
