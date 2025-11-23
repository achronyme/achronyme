//! Binary and unary operator compilation

use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::{AstNode, BinaryOp, UnaryOp};

impl Compiler {
    /// Compile binary operation
    pub(crate) fn compile_binary_op(
        &mut self,
        op: &BinaryOp,
        left: &AstNode,
        right: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Handle short-circuit operators separately
        match op {
            BinaryOp::And => return self.compile_and(left, right),
            BinaryOp::Or => return self.compile_or(left, right),
            _ => {}
        }

        // Regular binary operations
        let left_res = self.compile_expression(left)?;
        let right_res = self.compile_expression(right)?;
        let result_reg = self.registers.allocate()?;

        let opcode = match op {
            BinaryOp::Add => OpCode::Add,
            BinaryOp::Subtract => OpCode::Sub,
            BinaryOp::Multiply => OpCode::Mul,
            BinaryOp::Divide => OpCode::Div,
            BinaryOp::Modulo => OpCode::Mod,
            BinaryOp::Power => OpCode::Pow,
            BinaryOp::Eq => OpCode::Eq,
            BinaryOp::Neq => OpCode::Ne,
            BinaryOp::Lt => OpCode::Lt,
            BinaryOp::Lte => OpCode::Le,
            BinaryOp::Gt => OpCode::Gt,
            BinaryOp::Gte => OpCode::Ge,
            BinaryOp::And | BinaryOp::Or => unreachable!("Handled above"),
        };

        self.emit(encode_abc(
            opcode.as_u8(),
            result_reg,
            left_res.reg(),
            right_res.reg(),
        ));

        // Free ONLY if temporary
        if left_res.is_temp() {
            self.registers.free(left_res.reg());
        }
        if right_res.is_temp() {
            self.registers.free(right_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }

    /// Compile AND with short-circuit evaluation
    /// Pattern: left && right
    /// - If left is falsy, return left (don't evaluate right)
    /// - If left is truthy, return right
    fn compile_and(&mut self, left: &AstNode, right: &AstNode) -> Result<RegResult, CompileError> {
        // Compile left operand
        let left_res = self.compile_expression(left)?;

        // Allocate result register and move left value to it
        let result_reg = self.registers.allocate()?;
        self.emit_move(result_reg, left_res.reg());

        // Jump to end if left is falsy (short-circuit)
        let skip_jump = self.emit_jump_if_false(result_reg, 0);

        // Free left register if temporary
        if left_res.is_temp() {
            self.registers.free(left_res.reg());
        }

        // Left was truthy, evaluate right and store in result
        let right_res = self.compile_expression(right)?;
        self.emit_move(result_reg, right_res.reg());

        // Free right register if temporary
        if right_res.is_temp() {
            self.registers.free(right_res.reg());
        }

        // Patch the skip jump
        self.patch_jump(skip_jump);

        Ok(RegResult::temp(result_reg))
    }

    /// Compile OR with short-circuit evaluation
    /// Pattern: left || right
    /// - If left is truthy, return left (don't evaluate right)
    /// - If left is falsy, return right
    fn compile_or(&mut self, left: &AstNode, right: &AstNode) -> Result<RegResult, CompileError> {
        // Compile left operand
        let left_res = self.compile_expression(left)?;

        // Allocate result register and move left value to it
        let result_reg = self.registers.allocate()?;
        self.emit_move(result_reg, left_res.reg());

        // Jump to end if left is truthy (short-circuit)
        let skip_jump = self.emit_jump_if_true(result_reg, 0);

        // Free left register if temporary
        if left_res.is_temp() {
            self.registers.free(left_res.reg());
        }

        // Left was falsy, evaluate right and store in result
        let right_res = self.compile_expression(right)?;
        self.emit_move(result_reg, right_res.reg());

        // Free right register if temporary
        if right_res.is_temp() {
            self.registers.free(right_res.reg());
        }

        // Patch the skip jump
        self.patch_jump(skip_jump);

        Ok(RegResult::temp(result_reg))
    }

    /// Compile unary operation
    pub(crate) fn compile_unary_op(
        &mut self,
        op: &UnaryOp,
        operand: &AstNode,
    ) -> Result<RegResult, CompileError> {
        let operand_res = self.compile_expression(operand)?;
        let result_reg = self.registers.allocate()?;

        let opcode = match op {
            UnaryOp::Negate => OpCode::Neg,
            UnaryOp::Not => OpCode::Not,
        };

        self.emit(encode_abc(opcode.as_u8(), result_reg, operand_res.reg(), 0));

        // Free ONLY if temporary
        if operand_res.is_temp() {
            self.registers.free(operand_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }
}
