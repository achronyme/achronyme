use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use achronyme_parser::ast::*;
use vm::opcode::OpCode;

pub trait BinaryCompiler {
    fn compile_binop(&mut self, op: &BinOp, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError>;
    fn compile_and(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError>;
    fn compile_or(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError>;
}

impl BinaryCompiler for Compiler {
    fn compile_binop(&mut self, op: &BinOp, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError> {
        let left_reg = self.compile_expr(lhs)?;
        let right_reg = self.compile_expr(rhs)?;

        let opcode = match op {
            BinOp::Add => OpCode::Add,
            BinOp::Sub => OpCode::Sub,
            BinOp::Mul => OpCode::Mul,
            BinOp::Div => OpCode::Div,
            BinOp::Mod => OpCode::Mod,
            BinOp::Pow => OpCode::Pow,
            BinOp::Eq => OpCode::Eq,
            BinOp::Neq => OpCode::NotEq,
            BinOp::Lt => OpCode::Lt,
            BinOp::Le => OpCode::Le,
            BinOp::Gt => OpCode::Gt,
            BinOp::Ge => OpCode::Ge,
            // And/Or are handled separately via compile_and/compile_or
            BinOp::And | BinOp::Or => unreachable!(),
        };

        self.emit_abc(opcode, left_reg, left_reg, right_reg);
        self.free_reg(right_reg);
        Ok(left_reg)
    }

    fn compile_and(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError> {
        let left_reg = self.compile_expr(lhs)?;

        // Short-circuit: if left is false, skip right
        let jump_end = self.emit_jump(OpCode::JumpIfFalse, left_reg);

        let right_reg = self.compile_expr(rhs)?;
        self.emit_abc(OpCode::Move, left_reg, right_reg, 0);
        self.free_reg(right_reg);

        self.patch_jump(jump_end);

        Ok(left_reg)
    }

    fn compile_or(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError> {
        let left_reg = self.compile_expr(lhs)?;

        // Short-circuit: if left is true, skip right
        let skip_jump = self.emit_jump(OpCode::JumpIfFalse, left_reg);
        let end_jump = self.emit_jump(OpCode::Jump, 0);
        self.patch_jump(skip_jump);

        let right_reg = self.compile_expr(rhs)?;
        self.emit_abc(OpCode::Move, left_reg, right_reg, 0);
        self.free_reg(right_reg);

        self.patch_jump(end_jump);

        Ok(left_reg)
    }
}
