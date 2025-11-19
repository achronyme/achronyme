//! Control flow expression compilation (if, while)

use crate::compiler::context::LoopContext;
use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;

impl Compiler {
    /// Compile if expression
    pub(crate) fn compile_if(
        &mut self,
        condition: &AstNode,
        then_expr: &AstNode,
        else_expr: Option<&AstNode>,
    ) -> Result<RegResult, CompileError> {
        // Compile condition
        let cond_res = self.compile_expression(condition)?;

        // Jump to else if false
        let else_jump = self.emit_jump_if_false(cond_res.reg(), 0);

        // Free condition ONLY if temporary
        if cond_res.is_temp() {
            self.registers.free(cond_res.reg());
        }

        // Compile then branch
        let then_res = self.compile_expression(then_expr)?;
        let result_reg = self.registers.allocate()?;
        self.emit_move(result_reg, then_res.reg());

        // Free then result ONLY if temporary
        if then_res.is_temp() {
            self.registers.free(then_res.reg());
        }

        // Jump over else
        let end_jump = self.emit_jump(0);

        // Patch else jump
        self.patch_jump(else_jump);

        // Compile else branch
        if let Some(else_node) = else_expr {
            let else_res = self.compile_expression(else_node)?;
            self.emit_move(result_reg, else_res.reg());

            // Free else result ONLY if temporary
            if else_res.is_temp() {
                self.registers.free(else_res.reg());
            }
        } else {
            // No else branch, result is null
            self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));
        }

        // Patch end jump
        self.patch_jump(end_jump);

        Ok(RegResult::temp(result_reg))
    }

    /// Compile while loop
    pub(crate) fn compile_while(&mut self, condition: &AstNode, body: &AstNode) -> Result<RegResult, CompileError> {
        let loop_start = self.current_position();

        // Compile condition
        let cond_res = self.compile_expression(condition)?;

        // Jump to end if false
        let end_jump = self.emit_jump_if_false(cond_res.reg(), 0);

        // Free condition ONLY if temporary
        if cond_res.is_temp() {
            self.registers.free(cond_res.reg());
        }

        // Push loop context
        self.loops.push(LoopContext {
            start: loop_start,
            breaks: Vec::new(),
        });

        // Compile body
        let body_res = self.compile_expression(body)?;

        // Free body ONLY if temporary
        if body_res.is_temp() {
            self.registers.free(body_res.reg());
        }

        // Jump back to start
        // CRITICAL FIX: Compensate for IP advancement after reading JUMP instruction
        // When VM reads JUMP, IP advances +1, then applies offset to that advanced IP
        // Without the +1, we land one instruction AFTER loop_start, skipping condition reload
        let offset = -(self.current_position() as i16 - loop_start as i16 + 1);
        self.emit_jump(offset);

        // Patch end jump
        self.patch_jump(end_jump);

        // Pop loop context and patch breaks
        let loop_ctx = self.loops.pop().unwrap();
        for break_pos in loop_ctx.breaks {
            self.patch_jump(break_pos);
        }

        // While loop returns null
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));

        Ok(RegResult::temp(result_reg))
    }
}
