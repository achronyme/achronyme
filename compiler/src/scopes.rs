use crate::codegen::Compiler;

pub trait ScopeCompiler {
    fn begin_scope(&mut self);
    fn end_scope(&mut self);
    fn resolve_local(&self, name: &str) -> Option<(usize, u8)>;
    fn resolve_upvalue(&mut self, compiler_idx: usize, name: &str) -> Option<u8>;
}

impl ScopeCompiler for Compiler {
    fn begin_scope(&mut self) {
        self.current().scope_depth += 1;
    }

    fn end_scope(&mut self) {
        let func = self.current();
        func.scope_depth -= 1;
        let current_depth = func.scope_depth;

        // Pop locals that are out of scope
        // We need to know which ones to pop. Since they are ordered by creation,
        // we pop from the end until we hit a local with depth <= current_depth.
        let mut pop_count = 0;
        for i in (0..func.locals.len()).rev() {
            if func.locals[i].depth > current_depth {
                pop_count += 1;
            } else {
                break;
            }
        }

        for _ in 0..pop_count {
            if let Some(local) = func.locals.pop() {
                if local.is_captured {
                    func.emit_abx(vm::opcode::OpCode::CloseUpvalue, local.reg, 0);
                }
                // Hygiene: Free the register
                func.free_reg(local.reg);
            }
        }
    }

    fn resolve_local(&self, name: &str) -> Option<(usize, u8)> {
        self.current_ref().resolve_local(name)
    }

    fn resolve_upvalue(&mut self, compiler_idx: usize, name: &str) -> Option<u8> {
        if compiler_idx == 0 {
            return None; // Global scope has no upvalues
        }

        let parent_idx = compiler_idx - 1;

        // 1. Check parent's locals
        let parent_local = self.compilers[parent_idx].resolve_local(name);

        if let Some((idx, reg)) = parent_local {
            // Found in parent's locals -> Mark captured
            self.compilers[parent_idx].locals[idx].is_captured = true;

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
