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
        self.current_span = Some(expr.span().clone());
        match expr {
            // === Atoms ===
            Expr::Number { value, .. } => self.compile_number(value),
            Expr::FieldLit { value, radix, .. } => self.compile_field_lit(value, radix),
            Expr::BigIntLit {
                value,
                width,
                radix,
                ..
            } => self.compile_bigint_lit(value, *width, radix),
            Expr::StringLit { value, .. } => self.compile_string(value),
            Expr::Bool { value: true, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadTrue, reg, 0)?;
                self.set_reg_type(reg, crate::types::RegType::Bool)?;
                Ok(reg)
            }
            Expr::Bool { value: false, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadFalse, reg, 0)?;
                self.set_reg_type(reg, crate::types::RegType::Bool)?;
                Ok(reg)
            }
            Expr::Nil { .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0)?;
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
                    UnaryOp::Neg => self.emit_abc(OpCode::Neg, reg, reg, 0)?,
                    UnaryOp::Not => self.emit_abc(OpCode::LogNot, reg, reg, 0)?,
                }
                Ok(reg)
            }

            // === Postfix (Call, Index, DotAccess) ===
            Expr::Call {
                callee, args, span, ..
            } => {
                // If any arg has a keyword name, route to circuit call handler
                if args.iter().any(|a| a.name.is_some()) {
                    let name = match callee.as_ref() {
                        Expr::Ident { name, .. } => name,
                        _ => {
                            return Err(CompilerError::CompileError(
                                "keyword arguments require a simple function name".into(),
                                self.cur_span(),
                            ));
                        }
                    };
                    let kw_args: Vec<(String, Expr)> = args
                        .iter()
                        .map(|a| (a.name.clone().unwrap_or_default(), a.value.clone()))
                        .collect();
                    self.compile_circuit_call(name, &kw_args, span)
                } else {
                    let positional: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    self.compile_call(callee, &positional)
                }
            }
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
            Expr::Prove {
                name, body, params, ..
            } => self.compile_prove(body, params, name.as_deref()),

            // === Static access (Type::MEMBER) ===
            Expr::StaticAccess {
                type_name, member, ..
            } => self.compile_static_access(type_name, member),

            // CircuitCall removed — handled by Call with keyword args

            // === Error recovery placeholder ===
            Expr::Error { .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0)?;
                Ok(reg)
            }
        }
    }

    fn compile_expr_into(&mut self, expr: &Expr, target: u8) -> Result<(), CompilerError> {
        let reg = self.compile_expr(expr)?;
        if reg != target {
            self.emit_abc(OpCode::Move, target, reg, 0)?;
            self.free_reg(reg)?;
        }
        Ok(())
    }
}

// Private helpers
impl Compiler {
    fn compile_number(&mut self, value: &str) -> Result<u8, CompilerError> {
        let sp = self.cur_span();
        let val: i64 = value
            .parse()
            .map_err(|_| CompilerError::InvalidNumber(sp.clone()))?;
        if !(memory::I60_MIN..=memory::I60_MAX).contains(&val) {
            return Err(CompilerError::InvalidNumber(sp));
        }
        let reg = self.alloc_reg()?;
        let const_idx = self.add_constant(Value::int(val))?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
        self.set_reg_type(reg, crate::types::RegType::Int)?;
        Ok(reg)
    }

    fn compile_field_lit(&mut self, value: &str, radix: &FieldRadix) -> Result<u8, CompilerError> {
        let sp = self.cur_span();
        let fe = match radix {
            FieldRadix::Decimal => memory::FieldElement::from_decimal_str(value),
            FieldRadix::Hex => memory::FieldElement::from_hex_str(value),
            FieldRadix::Binary => memory::FieldElement::from_binary_str(value),
        }
        .ok_or(CompilerError::InvalidNumber(sp))?;
        let handle = self.intern_field(fe);
        let val = Value::field(handle);
        let const_idx = self.add_constant(val)?;
        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
        self.set_reg_type(reg, crate::types::RegType::Field)?;
        Ok(reg)
    }

    fn compile_bigint_lit(
        &mut self,
        value: &str,
        width: u16,
        radix: &BigIntRadix,
    ) -> Result<u8, CompilerError> {
        let sp = self.cur_span();
        let w = match width {
            256 => memory::BigIntWidth::W256,
            512 => memory::BigIntWidth::W512,
            _ => return Err(CompilerError::InvalidNumber(sp)),
        };
        let bi = match radix {
            BigIntRadix::Hex => memory::BigInt::from_hex_str(value, w),
            BigIntRadix::Decimal => memory::BigInt::from_decimal_str(value, w),
            BigIntRadix::Binary => memory::BigInt::from_binary_str(value, w),
        }
        .ok_or(CompilerError::InvalidNumber(self.cur_span()))?;
        let handle = self.intern_bigint(bi);
        let val = Value::bigint(handle);
        let const_idx = self.add_constant(val)?;
        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
        Ok(reg)
    }

    fn compile_string(&mut self, value: &str) -> Result<u8, CompilerError> {
        let processed = achronyme_parser::unescape(value);
        let handle = self.intern_string(&processed);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val)?;
        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
        self.set_reg_type(reg, crate::types::RegType::String)?;
        Ok(reg)
    }

    fn compile_ident(&mut self, name: &str) -> Result<u8, CompilerError> {
        let reg = self.alloc_reg()?;

        // 1. First check locals (including function parameters)
        if let Some((idx, local_reg)) = self.resolve_local(name) {
            let func = self.current()?;
            func.locals[idx].is_read = true;
            // Propagate type: prefer Local's type annotation, fall back to reg_types
            let src_type = match &func.locals[idx].type_ann {
                Some(ann) => crate::types::RegType::from_annotation(ann),
                None => func.get_reg_type(local_reg),
            };
            func.emit_abc(OpCode::Move, reg, local_reg, 0);
            func.set_reg_type(reg, src_type);
            Ok(reg)
        } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name) {
            // 2. Upvalue lookup — type unknown (crosses function boundary)
            self.emit_abx(OpCode::GetUpvalue, reg, upval_idx as u16)?;
            Ok(reg)
        } else {
            // 3. Fall back to global lookup (try plain name first, then prefixed)
            let idx = if let Some(entry) = self.global_symbols.get(name) {
                // Mark selectively imported name as used (for W005)
                if self.imported_names.contains_key(name) {
                    self.used_imported_names.insert(name.to_string());
                }
                entry.index
            } else if let Some(ref prefix) = self.module_prefix {
                let mangled = format!("{prefix}::{name}");
                self.global_symbols
                    .get(&mangled)
                    .ok_or_else(|| self.undefined_var_error(name))?
                    .index
            } else {
                return Err(self.undefined_var_error(name));
            };
            self.emit_abx(OpCode::GetGlobal, reg, idx)?;
            Ok(reg)
        }
    }

    fn compile_list(&mut self, elements: &[Expr]) -> Result<u8, CompilerError> {
        let target_reg = self.alloc_reg()?;
        let count = elements.len();
        let start_reg = self.current()?.reg_top;

        for (i, elem) in elements.iter().enumerate() {
            let reg = self.compile_expr(elem)?;
            if reg != start_reg.wrapping_add(i as u8) {
                return Err(CompilerError::CompilerLimitation(
                    "Register allocation fragmentation in list literal".into(),
                    self.cur_span(),
                ));
            }
        }

        if count > 255 {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }

        self.emit_abc(OpCode::BuildList, target_reg, start_reg, count as u8)?;

        for _ in 0..count {
            let top = self.current()?.reg_top - 1;
            self.free_reg(top)?;
        }

        Ok(target_reg)
    }

    fn compile_map(&mut self, pairs: &[(MapKey, Expr)]) -> Result<u8, CompilerError> {
        let count = pairs.len();

        if count > 127 {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }

        let target_reg = self.alloc_reg()?;

        let start_reg = if count > 0 {
            self.alloc_contiguous((count * 2) as u8)?
        } else {
            self.current()?.reg_top
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
            let const_idx = self.add_constant(key_val)?;

            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants(self.cur_span()));
            }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16)?;

            // Value
            self.compile_expr_into(value, val_reg)?;
        }

        self.emit_abc(OpCode::BuildMap, target_reg, start_reg, count as u8)?;

        if count > 0 {
            for _ in 0..(count * 2) {
                let top = self.current()?.reg_top - 1;
                self.free_reg(top)?;
            }
        }

        Ok(target_reg)
    }

    fn compile_call(&mut self, callee: &Expr, args: &[&Expr]) -> Result<u8, CompilerError> {
        // Detect method call pattern: expr.method(args) where method is known
        if let Expr::DotAccess { object, field, .. } = callee {
            // Check: field is a known method AND object is NOT an imported module alias
            let is_module_alias = if let Expr::Ident { name, .. } = object.as_ref() {
                self.imported_aliases.contains_key(name)
            } else {
                false
            };

            if self.known_methods.contains(field.as_str()) && !is_module_alias {
                return self.compile_method_call(object, field, args);
            }
        }

        let func_reg = self.compile_expr(callee)?;

        let arg_count = args.len();
        for arg in args {
            let _arg_reg = self.compile_expr(arg)?;
        }

        if arg_count > 255 {
            return Err(CompilerError::CompilerLimitation(
                format!("function call has {arg_count} arguments (maximum is 255)"),
                self.cur_span(),
            ));
        }

        self.emit_abc(OpCode::Call, func_reg, func_reg, arg_count as u8)?;

        for _ in 0..arg_count {
            let top = self.current()?.reg_top - 1;
            self.free_reg(top)?;
        }

        Ok(func_reg)
    }

    fn compile_method_call(
        &mut self,
        object: &Expr,
        method: &str,
        args: &[&Expr],
    ) -> Result<u8, CompilerError> {
        // 1. Allocate register for method name (will become result register)
        let name_reg = self.alloc_reg()?;

        // 2. Compile receiver into next register
        let recv_reg = self.compile_expr(object)?;
        debug_assert_eq!(recv_reg, name_reg + 1);

        // 3. Compile explicit arguments
        let arg_count = args.len();
        for arg in args {
            let _arg_reg = self.compile_expr(arg)?;
        }

        if arg_count > 255 {
            return Err(CompilerError::CompilerLimitation(
                format!("method call has {arg_count} arguments (maximum is 255)"),
                self.cur_span(),
            ));
        }

        // 4. LoadConst method name into name_reg
        let handle = self.intern_string(method);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val)?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, name_reg, const_idx as u16)?;

        // 5. Emit MethodCall: A=name_reg (result), B=recv_reg, C=arg_count
        self.emit_abc(OpCode::MethodCall, name_reg, recv_reg, arg_count as u8)?;

        // 6. Free arg registers (LIFO) then receiver
        for _ in 0..arg_count {
            let top = self.current()?.reg_top - 1;
            self.free_reg(top)?;
        }
        self.free_reg(recv_reg)?;

        // name_reg now holds the result
        Ok(name_reg)
    }

    fn compile_index_expr(&mut self, object: &Expr, index: &Expr) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_expr(index)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg)?;
        self.free_reg(key_reg)?;
        Ok(obj_reg)
    }

    fn compile_dot_access(&mut self, object: &Expr, field: &str) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_dot_key(field)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg)?;
        self.free_reg(key_reg)?;
        Ok(obj_reg)
    }

    fn compile_static_access(
        &mut self,
        type_name: &str,
        member: &str,
    ) -> Result<u8, CompilerError> {
        let reg = self.alloc_reg()?;
        match (type_name, member) {
            // Int::MAX, Int::MIN
            ("Int", "MAX") => {
                let val = Value::int(memory::I60_MAX);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            ("Int", "MIN") => {
                let val = Value::int(memory::I60_MIN);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // Field::ZERO, Field::ONE
            ("Field", "ZERO") => {
                let handle = self.intern_field(memory::FieldElement::ZERO);
                let val = Value::field(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            ("Field", "ONE") => {
                let fe = memory::FieldElement::from_u64(1);
                let handle = self.intern_field(fe);
                let val = Value::field(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // Field::ORDER — the BN254 Fr modulus as a string
            ("Field", "ORDER") => {
                let order_str =
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
                let handle = self.intern_string(order_str);
                let val = Value::string(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // BigInt::from_bits — resolve to a global (native function)
            ("BigInt", "from_bits") => {
                // Look up the global for from_bits (still a native global at this point)
                let idx = self
                    .global_symbols
                    .get("from_bits")
                    .map(|e| e.index)
                    .ok_or_else(|| {
                        CompilerError::CompileError(
                            "BigInt::from_bits is not available (from_bits native not found)"
                                .into(),
                            self.cur_span(),
                        )
                    })?;
                self.emit_abx(OpCode::GetGlobal, reg, idx)?;
            }
            _ => {
                // Check if type is known but member isn't
                let known_types = ["Int", "Field", "BigInt"];
                if known_types.contains(&type_name) {
                    return Err(CompilerError::CompileError(
                        format!("unknown static member: '{type_name}::{member}'"),
                        self.cur_span(),
                    ));
                }
                return Err(CompilerError::CompileError(
                    format!("unknown type: '{type_name}'"),
                    self.cur_span(),
                ));
            }
        }
        Ok(reg)
    }

    pub fn compile_dot_key(&mut self, name: &str) -> Result<u8, CompilerError> {
        let handle = self.intern_string(name);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val)?;
        let r = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, r, const_idx as u16)?;
        Ok(r)
    }
}
