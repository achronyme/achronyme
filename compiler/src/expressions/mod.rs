use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::functions::FunctionDefinitionCompiler;
use crate::scopes::ScopeCompiler;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub mod binary;

pub use binary::BinaryCompiler;

pub trait ExpressionCompiler {
    fn compile_expr(&mut self, expr: &Expr) -> Result<u8, CompilerError>;
    fn compile_expr_into(&mut self, expr: &Expr, target: u8) -> Result<(), CompilerError>;
}

impl ExpressionCompiler for Compiler {
    fn compile_expr(&mut self, expr: &Expr) -> Result<u8, CompilerError> {
        match expr {
            // === Atoms ===
            Expr::Number { value, .. } => self.compile_number(value),
            Expr::StringLit { value, .. } => self.compile_string(value),
            Expr::Bool { value: true, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadTrue, reg, 0);
                Ok(reg)
            }
            Expr::Bool { value: false, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadFalse, reg, 0);
                Ok(reg)
            }
            Expr::Nil { .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0);
                Ok(reg)
            }
            Expr::Ident { name, .. } => self.compile_ident(name),
            Expr::Array { elements, .. } => self.compile_list(elements),
            Expr::Map { pairs, .. } => self.compile_map(pairs),

            // === Binary operations ===
            Expr::BinOp {
                op: BinOp::And,
                lhs,
                rhs,
                ..
            } => self.compile_and(lhs, rhs),
            Expr::BinOp {
                op: BinOp::Or,
                lhs,
                rhs,
                ..
            } => self.compile_or(lhs, rhs),
            Expr::BinOp { op, lhs, rhs, .. } => self.compile_binop(op, lhs, rhs),

            // === Unary operations ===
            Expr::UnaryOp { op, operand, .. } => {
                let reg = self.compile_expr(operand)?;
                match op {
                    UnaryOp::Neg => self.emit_abc(OpCode::Neg, reg, reg, 0),
                    UnaryOp::Not => self.emit_abc(OpCode::LogNot, reg, reg, 0),
                }
                Ok(reg)
            }

            // === Postfix (Call, Index, DotAccess) ===
            Expr::Call { callee, args, .. } => self.compile_call(callee, args),
            Expr::Index { object, index, .. } => self.compile_index_expr(object, index),
            Expr::DotAccess { object, field, .. } => self.compile_dot_access(object, field),

            // === Control flow ===
            Expr::If {
                condition,
                then_block,
                else_branch,
                ..
            } => self.compile_if(condition, then_block, else_branch.as_ref()),
            Expr::While {
                condition, body, ..
            } => self.compile_while(condition, body),
            Expr::For {
                var,
                iterable,
                body,
                ..
            } => self.compile_for(var, iterable, body),
            Expr::Forever { body, .. } => self.compile_forever(body),
            Expr::Block(block) => {
                let reg = self.alloc_reg()?;
                self.compile_block(block, reg)?;
                Ok(reg)
            }

            // === Functions ===
            Expr::FnExpr {
                name, params, body, ..
            } => self.compile_fn_core(name.as_deref(), params, body),

            // === ZK ===
            Expr::Prove { body, source, .. } => self.compile_prove(body, source),
        }
    }

    fn compile_expr_into(&mut self, expr: &Expr, target: u8) -> Result<(), CompilerError> {
        let reg = self.compile_expr(expr)?;
        if reg != target {
            self.emit_abc(OpCode::Move, target, reg, 0);
            self.free_reg(reg);
        }
        Ok(())
    }
}

// Private helpers
impl Compiler {
    fn compile_number(&mut self, value: &str) -> Result<u8, CompilerError> {
        let val: i64 = value.parse().map_err(|_| CompilerError::InvalidNumber)?;
        let reg = self.alloc_reg()?;
        let const_idx = self.add_constant(Value::int(val));
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        Ok(reg)
    }

    fn compile_string(&mut self, value: &str) -> Result<u8, CompilerError> {
        let processed = achronyme_parser::unescape(value);
        let handle = self.intern_string(&processed);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val);
        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        Ok(reg)
    }

    fn compile_ident(&mut self, name: &str) -> Result<u8, CompilerError> {
        let reg = self.alloc_reg()?;

        // 1. First check locals (including function parameters)
        if let Some((_, local_reg)) = self.resolve_local(name) {
            self.emit_abc(OpCode::Move, reg, local_reg, 0);
            Ok(reg)
        } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name) {
            // 2. Upvalue lookup
            self.emit_abx(OpCode::GetUpvalue, reg, upval_idx as u16);
            Ok(reg)
        } else {
            // 3. Fall back to global lookup
            let idx = *self.global_symbols.get(name).ok_or_else(|| {
                CompilerError::UnknownOperator(format!("Undefined variable: {}", name))
            })?;
            self.emit_abx(OpCode::GetGlobal, reg, idx);
            Ok(reg)
        }
    }

    fn compile_list(&mut self, elements: &[Expr]) -> Result<u8, CompilerError> {
        let target_reg = self.alloc_reg()?;
        let count = elements.len();
        let start_reg = self.current().reg_top;

        for (i, elem) in elements.iter().enumerate() {
            let reg = self.compile_expr(elem)?;
            if reg != start_reg.wrapping_add(i as u8) {
                return Err(CompilerError::CompilerLimitation(
                    "Register allocation fragmentation in list literal".into(),
                ));
            }
        }

        if count > 255 {
            return Err(CompilerError::TooManyConstants);
        }

        self.emit_abc(OpCode::BuildList, target_reg, start_reg, count as u8);

        for _ in 0..count {
            let top = self.current().reg_top - 1;
            self.free_reg(top);
        }

        Ok(target_reg)
    }

    fn compile_map(&mut self, pairs: &[(MapKey, Expr)]) -> Result<u8, CompilerError> {
        let count = pairs.len();

        if count > 127 {
            return Err(CompilerError::TooManyConstants);
        }

        let target_reg = self.alloc_reg()?;

        let start_reg = if count > 0 {
            self.alloc_contiguous((count * 2) as u8)?
        } else {
            self.current().reg_top
        };

        for (i, (key, value)) in pairs.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // Key: map keys use raw value (ident name or string content)
            let key_str = match key {
                MapKey::Ident(s) => s.as_str(),
                MapKey::StringLit(s) => s.as_str(),
            };

            let key_handle = self.intern_string(key_str);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val);

            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants);
            }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16);

            // Value
            self.compile_expr_into(value, val_reg)?;
        }

        self.emit_abc(OpCode::BuildMap, target_reg, start_reg, count as u8);

        if count > 0 {
            for _ in 0..(count * 2) {
                let top = self.current().reg_top - 1;
                self.free_reg(top);
            }
        }

        Ok(target_reg)
    }

    fn compile_call(&mut self, callee: &Expr, args: &[Expr]) -> Result<u8, CompilerError> {
        let func_reg = self.compile_expr(callee)?;

        let arg_count = args.len();
        for arg in args {
            let _arg_reg = self.compile_expr(arg)?;
        }

        if arg_count > 255 {
            return Err(CompilerError::CompilerLimitation(format!(
                "function call has {arg_count} arguments (maximum is 255)"
            )));
        }

        self.emit_abc(OpCode::Call, func_reg, func_reg, arg_count as u8);

        for _ in 0..arg_count {
            let top = self.current().reg_top - 1;
            self.free_reg(top);
        }

        Ok(func_reg)
    }

    fn compile_index_expr(&mut self, object: &Expr, index: &Expr) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_expr(index)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg);
        self.free_reg(key_reg);
        Ok(obj_reg)
    }

    fn compile_dot_access(&mut self, object: &Expr, field: &str) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_dot_key(field)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg);
        self.free_reg(key_reg);
        Ok(obj_reg)
    }

    pub fn compile_dot_key(&mut self, name: &str) -> Result<u8, CompilerError> {
        let handle = self.intern_string(name);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val);
        let r = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }
        self.emit_abx(OpCode::LoadConst, r, const_idx as u16);
        Ok(r)
    }
}
