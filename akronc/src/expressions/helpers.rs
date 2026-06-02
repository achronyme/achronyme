use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::scopes::ScopeCompiler;
use crate::statements::circom_imports::CircomVmCallEmitter;
use achronyme_parser::ast::{BigIntRadix, Expr, FieldRadix, MapKey};
use akron::opcode::OpCode;
use memory::Value;

use super::ExpressionCompiler;

impl Compiler {
    pub(super) fn compile_number(&mut self, value: &str) -> Result<u8, CompilerError> {
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
        Ok(reg)
    }

    pub(super) fn compile_field_lit(
        &mut self,
        value: &str,
        radix: &FieldRadix,
    ) -> Result<u8, CompilerError> {
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
        Ok(reg)
    }

    pub(super) fn compile_bigint_lit(
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

    pub(super) fn compile_string(&mut self, value: &str) -> Result<u8, CompilerError> {
        let processed = achronyme_parser::unescape(value);
        let handle = self.intern_string(&processed);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val)?;
        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
        Ok(reg)
    }

    pub(super) fn compile_ident(&mut self, name: &str) -> Result<u8, CompilerError> {
        // Shadow-dispatch observation. If a resolver state was
        // installed or auto-built, look up the annotation for the
        // current Expr::Ident and record the hit on `resolver_hits`.
        // This is pure observation — dispatch itself is unchanged.
        // Tests read the trace to verify the resolver agrees with
        // the name-based lookup.
        if let (Some(resolved), Some(root_module), Some(expr_id)) = (
            self.resolved_program.as_ref(),
            self.resolver_root_module,
            self.current_expr_id,
        ) {
            if let Some(&sid) = resolved.annotations.get(&(root_module, expr_id)) {
                self.resolver_hits.push((expr_id, sid));
            }
        }

        let reg = self.alloc_reg()?;

        // 1. First check locals (including function parameters)
        if let Some((idx, local_reg)) = self.resolve_local(name) {
            self.current()?.locals[idx].is_read = true;
            self.emit_abc(OpCode::Move, reg, local_reg, 0)?;
            Ok(reg)
        } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name) {
            // 2. Upvalue lookup
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

    pub(super) fn compile_list(&mut self, elements: &[Expr]) -> Result<u8, CompilerError> {
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

    pub(super) fn compile_map(&mut self, pairs: &[(MapKey, Expr)]) -> Result<u8, CompilerError> {
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

    pub(super) fn compile_call(
        &mut self,
        callee: &Expr,
        args: &[&Expr],
    ) -> Result<u8, CompilerError> {
        // Circom template atomic curry in VM mode:
        //   Template(template_args)(signal_inputs)  ->  CallCircomTemplate
        //   P.Template(template_args)(signal_inputs) ->  CallCircomTemplate
        //
        // Parses as Call { callee: Call { callee: <ident|dot>, args: template_args }, args: inputs }.
        // Intercept before the normal call dispatch so the registered
        // selective / namespaced circom imports emit the dedicated
        // opcode instead of trying to go through the VM call path.
        if let Expr::Call {
            callee: inner_callee,
            args: inner_args,
            ..
        } = callee
        {
            if let Some((library_arc, template_name)) =
                self.try_resolve_circom_vm_call(inner_callee)
            {
                let template_arg_exprs: Vec<&Expr> = inner_args.iter().map(|a| &a.value).collect();
                return self.compile_circom_vm_call(
                    library_arc,
                    template_name,
                    &template_arg_exprs,
                    args,
                );
            }
        }

        // Detect method call pattern: expr.method(args) where method is known.
        //
        // `alias.func(...)` where `alias` is a module namespace import
        // is NO LONGER a valid call shape — the canonical syntax is
        // `alias::func(...)`, which is resolved at compile time against
        // the unified dispatch table. Emit a clear migration error
        // with a "did you mean" hint instead of silently falling
        // through to the generic DotAccess path (which used to route
        // through a runtime map lookup and couldn't be supported
        // inside prove blocks).
        if let Expr::DotAccess { object, field, .. } = callee {
            if let Expr::Ident { name, .. } = object.as_ref() {
                if self.imported_aliases.contains_key(name)
                    || self.circom_namespaces.contains_key(name)
                {
                    return Err(CompilerError::CompileError(
                        format!(
                            "use `{name}::{field}(...)` instead of `{name}.{field}(...)` \
                             — module-qualified calls now resolve at compile time via \
                             the `::` path operator"
                        ),
                        self.cur_span(),
                    ));
                }
            }

            if self.known_methods.contains(field.as_str()) {
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

    pub(super) fn compile_index_expr(
        &mut self,
        object: &Expr,
        index: &Expr,
    ) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_expr(index)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg)?;
        self.free_reg(key_reg)?;
        Ok(obj_reg)
    }

    pub(super) fn compile_dot_access(
        &mut self,
        object: &Expr,
        field: &str,
    ) -> Result<u8, CompilerError> {
        let obj_reg = self.compile_expr(object)?;
        let key_reg = self.compile_dot_key(field)?;
        self.emit_abc(OpCode::GetIndex, obj_reg, obj_reg, key_reg)?;
        self.free_reg(key_reg)?;
        Ok(obj_reg)
    }

    fn compile_dot_key(&mut self, name: &str) -> Result<u8, CompilerError> {
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
