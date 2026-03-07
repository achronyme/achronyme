use crate::codegen::Compiler;
use crate::error::CompilerError;
use achronyme_parser::Diagnostic;

pub trait ScopeCompiler {
    fn begin_scope(&mut self) -> Result<(), CompilerError>;
    fn end_scope(&mut self) -> Result<(), CompilerError>;
    fn resolve_local(&self, name: &str) -> Option<(usize, u8)>;
    fn resolve_upvalue(&mut self, compiler_idx: usize, name: &str) -> Option<u8>;
}

impl ScopeCompiler for Compiler {
    fn begin_scope(&mut self) -> Result<(), CompilerError> {
        self.current()?.scope_depth += 1;
        Ok(())
    }

    fn end_scope(&mut self) -> Result<(), CompilerError> {
        let warns = {
            let func = self.current()?;
            func.scope_depth -= 1;
            let current_depth = func.scope_depth;

            let mut pop_count = 0;
            for i in (0..func.locals.len()).rev() {
                if func.locals[i].depth > current_depth {
                    pop_count += 1;
                } else {
                    break;
                }
            }

            let mut warns = Vec::new();
            for _ in 0..pop_count {
                if let Some(local) = func.locals.pop() {
                    // Unused variable / unused-mut checks
                    if !local.name.starts_with('_') {
                        if let Some(ref span) = local.span {
                            if !local.is_read {
                                warns.push(
                                    Diagnostic::warning(
                                        format!("unused variable: `{}`", local.name),
                                        span.into(),
                                    )
                                    .with_code("W001")
                                    .with_note(format!(
                                        "if this is intentional, prefix with underscore: `_{}`",
                                        local.name
                                    )),
                                );
                            } else if local.is_mutable && !local.is_mutated {
                                warns.push(
                                    Diagnostic::warning(
                                        format!(
                                            "variable `{}` declared as mutable but never mutated",
                                            local.name
                                        ),
                                        span.into(),
                                    )
                                    .with_code("W002"),
                                );
                            }
                        }
                    }

                    if local.is_captured {
                        func.emit_abx(vm::opcode::OpCode::CloseUpvalue, local.reg, 0);
                    }
                    func.free_reg(local.reg);
                }
            }
            warns
        };

        self.warnings.extend(warns);
        Ok(())
    }

    fn resolve_local(&self, name: &str) -> Option<(usize, u8)> {
        self.current_ref().ok()?.resolve_local(name)
    }

    fn resolve_upvalue(&mut self, compiler_idx: usize, name: &str) -> Option<u8> {
        if compiler_idx == 0 {
            return None; // Global scope has no upvalues
        }

        let parent_idx = compiler_idx - 1;

        // 1. Check parent's locals
        let parent_local = self.compilers[parent_idx].resolve_local(name);

        if let Some((idx, reg)) = parent_local {
            // Found in parent's locals -> Mark captured and read
            self.compilers[parent_idx].locals[idx].is_captured = true;
            self.compilers[parent_idx].locals[idx].is_read = true;

            // Add to current compiler's upvalues
            return Some(self.compilers[compiler_idx].add_upvalue(true, reg));
        }

        // 2. Recursive check (Upvalue of Upvalue)
        if let Some(upval_idx) = self.resolve_upvalue(parent_idx, name) {
            return Some(self.compilers[compiler_idx].add_upvalue(false, upval_idx));
        }

        None
    }
}
