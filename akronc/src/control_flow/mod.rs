mod loops;
mod zk;

use crate::codegen::{is_terminator, Compiler};
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::statements::{stmt_span, StatementCompiler};
use achronyme_parser::ast::*;
use achronyme_parser::Diagnostic;
use akron::opcode::{instruction::encode_abx, OpCode};

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
        params: &[TypedParam],
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
        loops::enter_loop(self, start_label)
    }

    fn exit_loop(&mut self) -> Result<(), CompilerError> {
        loops::exit_loop(self)
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
        loops::compile_for(self, var, iterable, body)
    }

    fn compile_forever(&mut self, body: &Block) -> Result<u8, CompilerError> {
        loops::compile_forever(self, body)
    }

    fn compile_while(&mut self, condition: &Expr, body: &Block) -> Result<u8, CompilerError> {
        loops::compile_while(self, condition, body)
    }

    fn compile_prove(
        &mut self,
        body: &Block,
        params: &[TypedParam],
        name: Option<&str>,
    ) -> Result<u8, CompilerError> {
        zk::compile_prove(self, body, params, name)
    }

    fn compile_circuit_call(
        &mut self,
        name: &str,
        args: &[(String, Expr)],
        span: &Span,
    ) -> Result<u8, CompilerError> {
        zk::compile_circuit_call(self, name, args, span)
    }
}
