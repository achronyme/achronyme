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
            BinaryOp::And | BinaryOp::Or => {
                return Err(CompileError::Error(format!(
                    "Binary operation {:?} requires short-circuit evaluation",
                    op
                )))
            }
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
