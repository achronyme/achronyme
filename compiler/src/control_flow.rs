use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::statements::StatementCompiler;
use crate::types::{Local, LoopContext};
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::{instruction::encode_abx, OpCode};

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
    fn emit_jump(&mut self, op: OpCode, a: u8) -> usize;
    fn patch_jump(&mut self, idx: usize);
    fn enter_loop(&mut self, start_label: usize);
    fn exit_loop(&mut self);

    // Statements
    fn compile_break(&mut self) -> Result<(), CompilerError>;
    fn compile_continue(&mut self) -> Result<(), CompilerError>;

    // ZK
    fn compile_prove(&mut self, body: &Block, source: &str) -> Result<u8, CompilerError>;
}

impl ControlFlowCompiler for Compiler {
    fn emit_jump(&mut self, op: OpCode, a: u8) -> usize {
        self.emit_abx(op, a, 0xFFFF);
        self.current().bytecode.len() - 1
    }

    fn patch_jump(&mut self, idx: usize) {
        let bytecode = &mut self.current().bytecode;
        let jump_target = bytecode.len() as u16;
        let instr = bytecode[idx];
        // Re-encode with new Bx
        let opcode = (instr >> 24) as u8;
        let a = ((instr >> 16) & 0xFF) as u8;
        bytecode[idx] = encode_abx(opcode, a, jump_target);
    }

    fn enter_loop(&mut self, start_label: usize) {
        let depth = self.current().scope_depth;
        self.current().loop_stack.push(LoopContext {
            scope_depth: depth,
            start_label,
            break_jumps: Vec::new(),
        });
    }

    fn exit_loop(&mut self) {
        let loop_ctx = self
            .current()
            .loop_stack
            .pop()
            .expect("Loop stack underflow");
        for jump_idx in loop_ctx.break_jumps {
            self.patch_jump(jump_idx);
        }
    }

    fn compile_block(&mut self, block: &Block, target_reg: u8) -> Result<(), CompilerError> {
        let initial_reg_top = self.current().reg_top;
        self.begin_scope();
        let len = block.stmts.len();
        let mut last_processed = false;

        for (i, stmt) in block.stmts.iter().enumerate() {
            let is_last = i == len - 1;

            if is_last {
                match stmt {
                    Stmt::Expr(expr) => {
                        self.compile_expr_into(expr, target_reg)?;
                    }
                    _ => {
                        self.compile_stmt(stmt)?;
                        self.emit_abx(OpCode::LoadNil, target_reg, 0);
                    }
                }
                last_processed = true;
            } else {
                self.compile_stmt(stmt)?;
            }
        }

        if !last_processed {
            // Empty block
            self.emit_abx(OpCode::LoadNil, target_reg, 0);
        }

        self.end_scope();
        self.current().reg_top = initial_reg_top;
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
        let jump_else = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        self.free_reg(cond_reg);

        // 3. Then Block
        self.compile_block(then_block, target_reg)?;

        // 4. Jump -> End
        let jump_end = self.emit_jump(OpCode::Jump, 0);

        // 5. Else Start
        self.patch_jump(jump_else);

        if let Some(else_part) = else_branch {
            match else_part {
                ElseBranch::Block(block) => self.compile_block(block, target_reg)?,
                ElseBranch::If(if_expr) => {
                    let res = self.compile_expr(if_expr)?;
                    self.emit_abc(OpCode::Move, target_reg, res, 0);
                    self.free_reg(res);
                }
            }
        } else {
            self.emit_abx(OpCode::LoadNil, target_reg, 0);
        }

        // 6. End
        self.patch_jump(jump_end);

        Ok(target_reg)
    }

    fn compile_break(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self
            .current_ref()
            .loop_stack
            .last()
            .ok_or(CompilerError::CompileError("break outside of loop".into()))?;

        let target_depth = loop_ctx.scope_depth;

        let mut close_threshold = None;
        for (i, local) in self.current().locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break;
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }

        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0);
        }

        let jump = self.emit_jump(OpCode::Jump, 0);
        self.current()
            .loop_stack
            .last_mut()
            .unwrap()
            .break_jumps
            .push(jump);

        Ok(())
    }

    fn compile_continue(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self
            .current_ref()
            .loop_stack
            .last()
            .ok_or(CompilerError::CompileError(
                "continue outside of loop".into(),
            ))?;

        let target_depth = loop_ctx.scope_depth;
        let start_label = loop_ctx.start_label;

        let mut close_threshold = None;
        for (i, local) in self.current().locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break;
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }
        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0);
        }

        self.emit_abx(OpCode::Jump, 0, start_label as u16);
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
                    ));
                }

                let list_reg = self.alloc_reg()?;
                let start_elem = self.current().reg_top;

                for i in *start..*end {
                    let r = self.alloc_reg()?;
                    let ci = self.add_constant(Value::int(i as i64));
                    if ci > 0xFFFF {
                        return Err(CompilerError::TooManyConstants);
                    }
                    self.emit_abx(OpCode::LoadConst, r, ci as u16);
                }

                self.emit_abc(OpCode::BuildList, list_reg, start_elem, count as u8);

                for _ in 0..count {
                    let top = self.current().reg_top - 1;
                    self.free_reg(top);
                }

                list_reg
            }
        };

        let iter_reg = self.alloc_contiguous(2)?;
        let val_reg = iter_reg + 1;

        self.emit_abc(OpCode::GetIter, iter_reg, iter_src_reg, 0);

        let start_label = self.current().bytecode.len();
        self.enter_loop(start_label);

        let jump_exit_idx = self.emit_jump(OpCode::ForIter, iter_reg);

        self.begin_scope();
        let depth = self.current().scope_depth;
        self.current().locals.push(Local {
            name: var.to_string(),
            depth,
            is_captured: false,
            reg: val_reg,
        });

        let body_target = self.alloc_reg()?;
        self.compile_block(body, body_target)?;
        self.free_reg(body_target);

        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        self.patch_jump(jump_exit_idx);

        self.end_scope();

        self.exit_loop();

        self.free_reg(iter_reg);
        self.free_reg(iter_src_reg);

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);
        Ok(target_reg)
    }

    fn compile_forever(&mut self, body: &Block) -> Result<u8, CompilerError> {
        let start_label = self.current().bytecode.len();
        self.enter_loop(start_label);

        let body_reg = self.alloc_reg()?;
        self.compile_block(body, body_reg)?;
        self.free_reg(body_reg);

        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        self.exit_loop();

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);
        Ok(target_reg)
    }

    fn compile_while(&mut self, condition: &Expr, body: &Block) -> Result<u8, CompilerError> {
        let start_label = self.current().bytecode.len();

        let cond_reg = self.compile_expr(condition)?;

        let jump_end = self.emit_jump(OpCode::JumpIfFalse, cond_reg);

        self.free_reg(cond_reg);

        self.enter_loop(start_label);

        let body_reg = self.alloc_reg()?;
        self.compile_block(body, body_reg)?;
        self.free_reg(body_reg);

        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        self.patch_jump(jump_end);

        self.exit_loop();

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);

        Ok(target_reg)
    }

    fn compile_prove(&mut self, body: &Block, source: &str) -> Result<u8, CompilerError> {
        // Walk body stmts directly to find public/witness declarations
        let capture_names = prescan_prove_block(body)?;

        let count = capture_names.len();
        if count > 127 {
            return Err(CompilerError::CompilerLimitation(
                "prove block captures too many variables".into(),
            ));
        }

        let map_reg = self.alloc_reg()?;

        if count > 0 {
            let start_reg = self.alloc_contiguous((count * 2) as u8)?;

            for (i, name) in capture_names.iter().enumerate() {
                let key_reg = start_reg + (i as u8 * 2);
                let val_reg = key_reg + 1;

                // Key: string constant
                let key_handle = self.intern_string(name);
                let key_val = Value::string(key_handle);
                let key_idx = self.add_constant(key_val);
                if key_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants);
                }
                self.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16);

                // Value: resolve from current scope
                if let Some((_, local_reg)) = self.resolve_local(name) {
                    self.emit_abc(OpCode::Move, val_reg, local_reg, 0);
                } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name)
                {
                    self.emit_abx(OpCode::GetUpvalue, val_reg, upval_idx as u16);
                } else if let Some(&global_idx) = self.global_symbols.get(name) {
                    self.emit_abx(OpCode::GetGlobal, val_reg, global_idx);
                } else {
                    return Err(CompilerError::CompileError(format!(
                        "prove: variable `{name}` not found in scope"
                    )));
                }
            }

            self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8);

            for _ in 0..(count * 2) {
                let top = self.current().reg_top - 1;
                self.free_reg(top);
            }
        } else {
            // Empty capture map
            let start = self.current().reg_top;
            self.emit_abc(OpCode::BuildMap, map_reg, start, 0);
        }

        // Store block source as string constant.
        // The source includes the `prove` keyword; strip it so the handler
        // receives source starting with `{`.
        let block_source = &source[source.find('{').unwrap_or(0)..];
        let src_handle = self.intern_string(block_source);
        let src_val = Value::string(src_handle);
        let src_idx = self.add_constant(src_val);
        if src_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }

        // Emit Prove R[map_reg], K[src_idx]
        self.emit_abx(OpCode::Prove, map_reg, src_idx as u16);

        Ok(map_reg)
    }
}

/// Walk prove block AST to extract public/witness declaration names.
///
/// Supports array syntax `x[N]` which expands to `x_0, x_1, ..., x_{N-1}`.
fn prescan_prove_block(block: &Block) -> Result<Vec<String>, CompilerError> {
    let mut names = Vec::new();

    for stmt in &block.stmts {
        match stmt {
            Stmt::PublicDecl { names: decls, .. } | Stmt::WitnessDecl { names: decls, .. } => {
                for decl in decls {
                    if let Some(n) = decl.array_size {
                        if n > 10_000 {
                            return Err(CompilerError::CompilerLimitation(format!(
                                "array size {n} exceeds maximum of 10,000"
                            )));
                        }
                        for i in 0..n {
                            names.push(format!("{}_{i}", decl.name));
                        }
                    } else {
                        names.push(decl.name.clone());
                    }
                }
            }
            _ => {}
        }
    }

    Ok(names)
}
