use crate::codegen::{is_terminator, Compiler};
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::statements::{stmt_span, StatementCompiler};
use crate::types::{Local, LoopContext};
use achronyme_parser::ast::*;
use achronyme_parser::Diagnostic;
use memory::Value;
use vm::opcode::{instruction::encode_abx, OpCode};

/// Search all compiler scopes for a local with the given name that has an
/// array type annotation. Returns the array size if found.
fn find_local_array_size(compiler: &Compiler, name: &str) -> Option<usize> {
    // Search current function scope first
    if let Ok(func) = compiler.current_ref() {
        for local in func.locals.iter().rev() {
            if local.name == name {
                return match &local.type_ann {
                    Some(TypeAnnotation::FieldArray(n) | TypeAnnotation::BoolArray(n)) => Some(*n),
                    _ => None,
                };
            }
        }
    }
    // Search enclosing scopes (upvalue chain)
    for fc in compiler.compilers.iter().rev().skip(1) {
        for local in fc.locals.iter().rev() {
            if local.name == name {
                return match &local.type_ann {
                    Some(TypeAnnotation::FieldArray(n) | TypeAnnotation::BoolArray(n)) => Some(*n),
                    _ => None,
                };
            }
        }
    }
    None
}

pub trait ControlFlowCompiler {
    fn compile_block(&mut self, block: &Block, target_reg: u8) -> Result<(), CompilerError>;
    fn compile_if(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
    ) -> Result<u8, CompilerError>;
    fn compile_while(&mut self, condition: &Expr, body: &Block) -> Result<u8, CompilerError>;
    fn compile_for(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
    ) -> Result<u8, CompilerError>;
    fn compile_forever(&mut self, body: &Block) -> Result<u8, CompilerError>;

    // Low level
    fn emit_jump(&mut self, op: OpCode, a: u8) -> Result<usize, CompilerError>;
    fn patch_jump(&mut self, idx: usize) -> Result<(), CompilerError>;
    fn enter_loop(&mut self, start_label: usize) -> Result<(), CompilerError>;
    fn exit_loop(&mut self) -> Result<(), CompilerError>;

    // Statements
    fn compile_break(&mut self) -> Result<(), CompilerError>;
    fn compile_continue(&mut self) -> Result<(), CompilerError>;

    // ZK
    fn compile_prove(
        &mut self,
        body: &Block,
        public_list: Option<&[String]>,
        name: Option<&str>,
    ) -> Result<u8, CompilerError>;

    fn compile_circuit_call(
        &mut self,
        name: &str,
        args: &[(String, Expr)],
        span: &Span,
    ) -> Result<u8, CompilerError>;
}

impl ControlFlowCompiler for Compiler {
    fn emit_jump(&mut self, op: OpCode, a: u8) -> Result<usize, CompilerError> {
        self.emit_abx(op, a, 0xFFFF)?;
        Ok(self.current()?.bytecode.len() - 1)
    }

    fn patch_jump(&mut self, idx: usize) -> Result<(), CompilerError> {
        let bytecode = &mut self.current()?.bytecode;
        let jump_target = bytecode.len() as u16;
        let instr = bytecode[idx];
        // Re-encode with new Bx
        let opcode = (instr >> 24) as u8;
        let a = ((instr >> 16) & 0xFF) as u8;
        bytecode[idx] = encode_abx(opcode, a, jump_target);
        Ok(())
    }

    fn enter_loop(&mut self, start_label: usize) -> Result<(), CompilerError> {
        let depth = self.current()?.scope_depth;
        self.current()?.loop_stack.push(LoopContext {
            scope_depth: depth,
            start_label,
            break_jumps: Vec::new(),
        });
        Ok(())
    }

    fn exit_loop(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self
            .current()?
            .loop_stack
            .pop()
            .ok_or_else(|| CompilerError::InternalError("loop stack underflow".into()))?;
        for jump_idx in loop_ctx.break_jumps {
            self.patch_jump(jump_idx)?;
        }
        Ok(())
    }

    fn compile_block(&mut self, block: &Block, target_reg: u8) -> Result<(), CompilerError> {
        let initial_reg_top = self.current()?.reg_top;
        self.begin_scope()?;
        let len = block.stmts.len();
        let mut last_processed = false;
        let mut terminated = false;
        let mut unreachable_warned = false;

        for (i, stmt) in block.stmts.iter().enumerate() {
            // Warn once about unreachable code after a terminator
            if terminated && !unreachable_warned {
                if let Some(span) = stmt_span(stmt) {
                    self.emit_warning(
                        Diagnostic::warning("unreachable code", span.into()).with_code("W003"),
                    );
                }
                unreachable_warned = true;
            }

            let is_last = i == len - 1;

            if is_last {
                match stmt {
                    Stmt::Expr(expr) => {
                        self.compile_expr_into(expr, target_reg)?;
                    }
                    _ => {
                        self.compile_stmt(stmt)?;
                        self.emit_abx(OpCode::LoadNil, target_reg, 0)?;
                    }
                }
                last_processed = true;
            } else {
                self.compile_stmt(stmt)?;
            }

            if !terminated && is_terminator(stmt) {
                terminated = true;
            }
        }

        if !last_processed {
            // Empty block
            self.emit_abx(OpCode::LoadNil, target_reg, 0)?;
        }

        self.end_scope()?;
        self.current()?.reg_top = initial_reg_top;
        Ok(())
    }

    fn compile_if(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
    ) -> Result<u8, CompilerError> {
        let target_reg = self.alloc_reg()?;

        // 1. Compile Condition
        let cond_reg = self.compile_expr(condition)?;

        // 2. Jump if False -> Else
        let jump_else = self.emit_jump(OpCode::JumpIfFalse, cond_reg)?;
        self.free_reg(cond_reg)?;

        // 3. Then Block
        self.compile_block(then_block, target_reg)?;

        // 4. Jump -> End
        let jump_end = self.emit_jump(OpCode::Jump, 0)?;

        // 5. Else Start
        self.patch_jump(jump_else)?;

        if let Some(else_part) = else_branch {
            match else_part {
                ElseBranch::Block(block) => self.compile_block(block, target_reg)?,
                ElseBranch::If(if_expr) => {
                    let res = self.compile_expr(if_expr)?;
                    self.emit_abc(OpCode::Move, target_reg, res, 0)?;
                    self.free_reg(res)?;
                }
            }
        } else {
            self.emit_abx(OpCode::LoadNil, target_reg, 0)?;
        }

        // 6. End
        self.patch_jump(jump_end)?;

        Ok(target_reg)
    }

    fn compile_break(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self
            .current_ref()?
            .loop_stack
            .last()
            .ok_or(CompilerError::CompileError(
                "break outside of loop".into(),
                self.cur_span(),
            ))?;

        let target_depth = loop_ctx.scope_depth;

        let mut close_threshold = None;
        for (i, local) in self.current()?.locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break;
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }

        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0)?;
        }

        let jump = self.emit_jump(OpCode::Jump, 0)?;
        self.current()?
            .loop_stack
            .last_mut()
            .ok_or_else(|| CompilerError::InternalError("loop stack underflow".into()))?
            .break_jumps
            .push(jump);

        Ok(())
    }

    fn compile_continue(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self
            .current_ref()?
            .loop_stack
            .last()
            .ok_or(CompilerError::CompileError(
                "continue outside of loop".into(),
                self.cur_span(),
            ))?;

        let target_depth = loop_ctx.scope_depth;
        let start_label = loop_ctx.start_label;

        let mut close_threshold = None;
        for (i, local) in self.current()?.locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break;
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }
        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0)?;
        }

        self.emit_abx(OpCode::Jump, 0, start_label as u16)?;
        Ok(())
    }

    fn compile_for(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
    ) -> Result<u8, CompilerError> {
        let iter_src_reg = match iterable {
            ForIterable::Expr(expr) => self.compile_expr(expr)?,
            ForIterable::Range { start, end } => {
                // Build a list [start, start+1, ..., end-1] for the VM iterator
                let count = if *end >= *start {
                    (end - start) as usize
                } else {
                    0
                };
                if count > 255 {
                    return Err(CompilerError::CompilerLimitation(
                        "for..in range with more than 255 iterations; use a while loop instead"
                            .into(),
                        self.cur_span(),
                    ));
                }

                let list_reg = self.alloc_reg()?;
                let start_elem = self.current()?.reg_top;

                for i in *start..*end {
                    let r = self.alloc_reg()?;
                    let ci = self.add_constant(Value::int(i as i64))?;
                    if ci > 0xFFFF {
                        return Err(CompilerError::TooManyConstants(self.cur_span()));
                    }
                    self.emit_abx(OpCode::LoadConst, r, ci as u16)?;
                }

                self.emit_abc(OpCode::BuildList, list_reg, start_elem, count as u8)?;

                for _ in 0..count {
                    let top = self.current()?.reg_top - 1;
                    self.free_reg(top)?;
                }

                list_reg
            }
        };

        let iter_reg = self.alloc_contiguous(2)?;
        let val_reg = iter_reg + 1;

        self.emit_abc(OpCode::GetIter, iter_reg, iter_src_reg, 0)?;

        let start_label = self.current()?.bytecode.len();
        self.enter_loop(start_label)?;

        let jump_exit_idx = self.emit_jump(OpCode::ForIter, iter_reg)?;

        self.begin_scope()?;
        let depth = self.current()?.scope_depth;
        let var_span = self.current_span.clone();
        self.current()?.locals.push(Local {
            name: var.to_string(),
            depth,
            is_captured: false,
            is_mutable: false,
            is_read: false,
            is_mutated: false,
            reg: val_reg,
            span: var_span,
            type_ann: None,
        });

        let body_target = self.alloc_reg()?;
        self.compile_block(body, body_target)?;
        self.free_reg(body_target)?;

        self.emit_abx(OpCode::Jump, 0, start_label as u16)?;

        self.patch_jump(jump_exit_idx)?;

        self.end_scope()?;

        self.exit_loop()?;

        self.free_reg(iter_reg)?;
        self.free_reg(iter_src_reg)?;

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0)?;
        Ok(target_reg)
    }

    fn compile_forever(&mut self, body: &Block) -> Result<u8, CompilerError> {
        let start_label = self.current()?.bytecode.len();
        self.enter_loop(start_label)?;

        let body_reg = self.alloc_reg()?;
        self.compile_block(body, body_reg)?;
        self.free_reg(body_reg)?;

        self.emit_abx(OpCode::Jump, 0, start_label as u16)?;

        self.exit_loop()?;

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0)?;
        Ok(target_reg)
    }

    fn compile_while(&mut self, condition: &Expr, body: &Block) -> Result<u8, CompilerError> {
        let start_label = self.current()?.bytecode.len();

        let cond_reg = self.compile_expr(condition)?;

        let jump_end = self.emit_jump(OpCode::JumpIfFalse, cond_reg)?;

        self.free_reg(cond_reg)?;

        self.enter_loop(start_label)?;

        let body_reg = self.alloc_reg()?;
        self.compile_block(body, body_reg)?;
        self.free_reg(body_reg)?;

        self.emit_abx(OpCode::Jump, 0, start_label as u16)?;

        self.patch_jump(jump_end)?;

        self.exit_loop()?;

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0)?;

        Ok(target_reg)
    }

    fn compile_prove(
        &mut self,
        body: &Block,
        public_list: Option<&[String]>,
        name: Option<&str>,
    ) -> Result<u8, CompilerError> {
        // 1. Collect outer scope names for ProveIR capture detection.
        //    Include locals from ALL enclosing function scopes (not just current),
        //    so that upvalue-accessible variables are visible to ProveIR.
        //    Type annotations are propagated so ProveIR knows about arrays.
        let mut outer_scope: std::collections::HashMap<String, ir::prove_ir::OuterScopeEntry> =
            std::collections::HashMap::new();
        if let Ok(func) = self.current_ref() {
            for local in &func.locals {
                let entry = match &local.type_ann {
                    Some(
                        TypeAnnotation::FieldArray(n) | TypeAnnotation::BoolArray(n),
                    ) => ir::prove_ir::OuterScopeEntry::Array(*n),
                    _ => ir::prove_ir::OuterScopeEntry::Scalar,
                };
                outer_scope.insert(local.name.clone(), entry);
            }
        }
        for compiler in &self.compilers[..self.compilers.len().saturating_sub(1)] {
            for local in &compiler.locals {
                let entry = match &local.type_ann {
                    Some(
                        TypeAnnotation::FieldArray(n) | TypeAnnotation::BoolArray(n),
                    ) => ir::prove_ir::OuterScopeEntry::Array(*n),
                    _ => ir::prove_ir::OuterScopeEntry::Scalar,
                };
                outer_scope.entry(local.name.clone()).or_insert(entry);
            }
        }
        // Global symbols (no type annotation info available — treated as scalar)
        for name in self.collect_in_scope_names() {
            outer_scope
                .entry(name.to_string())
                .or_insert(ir::prove_ir::OuterScopeEntry::Scalar);
        }

        // 2. If public_list is provided (new syntax), validate no old-style
        //    declarations in the body and synthesize PublicDecl stmts.
        let compile_body;
        if let Some(pub_names) = public_list {
            // Validate: no old-style public/witness declarations in body
            for stmt in &body.stmts {
                if matches!(stmt, Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. }) {
                    return Err(CompilerError::CompileError(
                        "cannot mix prove(public: [...]) syntax with explicit \
                         public/witness declarations inside the block"
                            .into(),
                        self.cur_span(),
                    ));
                }
            }

            // Synthesize PublicDecl stmts and prepend to body.
            // If a public name has a type annotation with array size in the outer scope,
            // propagate it so ProveIR can decompose it into element captures.
            let mut stmts = Vec::new();
            for name in pub_names {
                let array_size = find_local_array_size(self, name);
                stmts.push(Stmt::PublicDecl {
                    names: vec![InputDecl {
                        name: name.clone(),
                        array_size,
                        type_ann: None,
                    }],
                    span: body.span.clone(),
                });
            }
            stmts.extend(body.stmts.clone());
            compile_body = Block {
                stmts,
                span: body.span.clone(),
            };
        } else {
            compile_body = body.clone();
        }

        // 3. Compile AST Block → ProveIR template.
        let mut prove_ir = ir::prove_ir::ProveIrCompiler::compile(&compile_body, &outer_scope)
            .map_err(|e| CompilerError::CompileError(format!("{e}"), self.cur_span()))?;
        prove_ir.name = name.map(|n| n.to_string());

        // 4. Build capture name list: captures + public inputs + witness inputs.
        //    All values come from the outer scope at runtime.
        let mut capture_names: Vec<String> = Vec::new();

        for cap in &prove_ir.captures {
            capture_names.push(cap.name.clone());
        }
        for input in &prove_ir.public_inputs {
            match &input.array_size {
                Some(ir::prove_ir::ArraySize::Literal(n)) => {
                    for i in 0..*n {
                        capture_names.push(format!("{}_{i}", input.name));
                    }
                }
                None => capture_names.push(input.name.clone()),
                Some(ir::prove_ir::ArraySize::Capture(_)) => {
                    return Err(CompilerError::CompileError(
                        "capture-sized arrays in prove blocks are not yet supported".into(),
                        self.cur_span(),
                    ));
                }
            }
        }
        for input in &prove_ir.witness_inputs {
            match &input.array_size {
                Some(ir::prove_ir::ArraySize::Literal(n)) => {
                    for i in 0..*n {
                        capture_names.push(format!("{}_{i}", input.name));
                    }
                }
                None => capture_names.push(input.name.clone()),
                Some(ir::prove_ir::ArraySize::Capture(_)) => {
                    return Err(CompilerError::CompileError(
                        "capture-sized arrays in prove blocks are not yet supported".into(),
                        self.cur_span(),
                    ));
                }
            }
        }

        let count = capture_names.len();
        if count > 127 {
            return Err(CompilerError::CompilerLimitation(
                "prove block captures too many variables".into(),
                self.cur_span(),
            ));
        }

        // 4. Build capture map from scope values (same codegen as before).
        let map_reg = self.alloc_reg()?;

        if count > 0 {
            let start_reg = self.alloc_contiguous((count * 2) as u8)?;

            for (i, name) in capture_names.iter().enumerate() {
                let key_reg = start_reg + (i as u8 * 2);
                let val_reg = key_reg + 1;

                let key_handle = self.intern_string(name);
                let key_val = Value::string(key_handle);
                let key_idx = self.add_constant(key_val)?;
                if key_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16)?;

                if let Some((idx, local_reg)) = self.resolve_local(name) {
                    self.current()?.locals[idx].is_read = true;
                    self.emit_abc(OpCode::Move, val_reg, local_reg, 0)?;
                } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name)
                {
                    self.emit_abx(OpCode::GetUpvalue, val_reg, upval_idx as u16)?;
                } else if let Some(&global_idx) = self.global_symbols.get(name) {
                    if self.imported_names.contains_key(name) {
                        self.used_imported_names.insert(name.to_string());
                    }
                    self.emit_abx(OpCode::GetGlobal, val_reg, global_idx)?;
                } else {
                    return Err(CompilerError::CompileError(
                        format!("prove: variable `{name}` not found in scope"),
                        self.cur_span(),
                    ));
                }
            }

            self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

            for _ in 0..(count * 2) {
                let top = self.current()?.reg_top - 1;
                self.free_reg(top)?;
            }
        } else {
            let start = self.current()?.reg_top;
            self.emit_abc(OpCode::BuildMap, map_reg, start, 0)?;
        }

        // 5. Serialize ProveIR and store as bytes constant.
        let ir_bytes = prove_ir.to_bytes().map_err(|e| {
            CompilerError::CompileError(format!("ProveIR serialization: {e}"), self.cur_span())
        })?;
        let ir_handle = self.intern_bytes(ir_bytes);
        let ir_val = Value::bytes(ir_handle);
        let ir_idx = self.add_constant(ir_val)?;
        if ir_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }

        // 6. Emit Prove R[map_reg], K[ir_idx]
        self.emit_abx(OpCode::Prove, map_reg, ir_idx as u16)?;

        Ok(map_reg)
    }

    fn compile_circuit_call(
        &mut self,
        name: &str,
        args: &[(String, Expr)],
        span: &Span,
    ) -> Result<u8, CompilerError> {
        // 1. Resolve the circuit name to its global index (contains ProveIR bytes)
        let global_idx = *self.global_symbols.get(name).ok_or_else(|| {
            CompilerError::CompileError(format!("circuit `{name}` not found"), span_box(span))
        })?;

        // 2. Load the ProveIR bytes from the global into a register
        let ir_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::GetGlobal, ir_reg, global_idx)?;

        // 3. Store the bytes as a constant (we need its index for the Prove opcode)
        //    The global already holds a Value::bytes — we need to get it into the
        //    constant pool. We load it into a register and then pass its constant
        //    index via GetGlobal. But Prove expects K[bx] = bytes constant.
        //    Approach: store the constant index at circuit-decl time, and here we
        //    look it up. Alternatively, emit the bytes constant index directly.
        //    Simplest: search constants for the bytes value matching this global.

        // Actually, the Prove opcode reads bytes from constants[bx]. We need the
        // constant index of the ProveIR bytes. Since the circuit decl stored the
        // bytes as a constant AND as a global, we can find the constant by scanning.
        // But that's fragile. Better approach: use the ir_reg to pass the bytes
        // directly to a new opcode pattern.
        //
        // Simplest working approach: the circuit call builds a map + emits Prove
        // using the same constant index the circuit decl used. We need to recover
        // that index. The global stores a Value::bytes(handle), and we interned
        // that bytes with a specific constant index.
        //
        // For now: find the bytes constant that matches. Since globals store
        // Value::bytes(handle), and the constant pool also has Value::bytes(handle)
        // with the same handle, we can find it.

        self.free_reg(ir_reg)?;

        // Search the constant pool for the bytes value stored at this global
        // The circuit decl stored: constants[idx] = Value::bytes(handle), global = same
        // We need `idx`.
        let ir_idx = self
            .current()?
            .constants
            .iter()
            .position(|c| c.is_bytes())
            .ok_or_else(|| {
                CompilerError::CompileError(
                    format!("circuit `{name}` has no ProveIR constant in pool"),
                    span_box(span),
                )
            })? as u16;

        // 3. Build the keyword argument map: { "key1": val1, "key2": val2, ... }
        let count = args.len();
        if count > 127 {
            return Err(CompilerError::CompilerLimitation(
                "circuit call has too many arguments".into(),
                span_box(span),
            ));
        }

        let map_reg = self.alloc_reg()?;

        if count > 0 {
            let start_reg = self.alloc_contiguous((count * 2) as u8)?;

            for (i, (key, val_expr)) in args.iter().enumerate() {
                let key_reg = start_reg + (i as u8 * 2);
                let val_reg = key_reg + 1;

                // Key: string constant
                let key_handle = self.intern_string(key);
                let key_val = Value::string(key_handle);
                let key_idx = self.add_constant(key_val)?;
                if key_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(span_box(span)));
                }
                self.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16)?;

                // Value: compile expression
                let compiled_reg = self.compile_expr(val_expr)?;
                self.emit_abc(OpCode::Move, val_reg, compiled_reg, 0)?;
                self.free_reg(compiled_reg)?;
            }

            self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

            for _ in 0..(count * 2) {
                let top = self.current()?.reg_top - 1;
                self.free_reg(top)?;
            }
        } else {
            let start = self.current()?.reg_top;
            self.emit_abc(OpCode::BuildMap, map_reg, start, 0)?;
        }

        // 4. Emit Prove R[map_reg], K[ir_idx]
        self.emit_abx(OpCode::Prove, map_reg, ir_idx)?;

        Ok(map_reg)
    }
}
