use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::types::RegType;
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

        let left_type = self.get_reg_type(left_reg)?;
        let right_type = self.get_reg_type(right_reg)?;
        let both_int = left_type == RegType::Int && right_type == RegType::Int;

        let opcode = match op {
            BinOp::Add => {
                if both_int {
                    OpCode::AddInt
                } else {
                    OpCode::Add
                }
            }
            BinOp::Sub => {
                if both_int {
                    OpCode::SubInt
                } else {
                    OpCode::Sub
                }
            }
            BinOp::Mul => {
                if both_int {
                    OpCode::MulInt
                } else {
                    OpCode::Mul
                }
            }
            BinOp::Div => {
                if both_int {
                    OpCode::DivInt
                } else {
                    OpCode::Div
                }
            }
            BinOp::Mod => {
                if both_int {
                    OpCode::ModInt
                } else {
                    OpCode::Mod
                }
            }
            BinOp::Pow => OpCode::Pow, // complex type dispatch, skip specialization
            BinOp::Eq => {
                if both_int {
                    OpCode::EqInt
                } else {
                    OpCode::Eq
                }
            }
            BinOp::Neq => {
                if both_int {
                    OpCode::NeqInt
                } else {
                    OpCode::NotEq
                }
            }
            BinOp::Lt => {
                if both_int {
                    OpCode::LtInt
                } else {
                    OpCode::Lt
                }
            }
            BinOp::Le => {
                if both_int {
                    OpCode::LeInt
                } else {
                    OpCode::Le
                }
            }
            BinOp::Gt => {
                if both_int {
                    OpCode::GtInt
                } else {
                    OpCode::Gt
                }
            }
            BinOp::Ge => {
                if both_int {
                    OpCode::GeInt
                } else {
                    OpCode::Ge
                }
            }
            // And/Or are handled separately via compile_and/compile_or
            BinOp::And | BinOp::Or => unreachable!(),
        };

        // Set result type
        let result_type = match op {
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                if both_int {
                    RegType::Int
                } else {
                    RegType::Unknown
                }
            }
            BinOp::Eq | BinOp::Neq | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                RegType::Bool
            }
            _ => RegType::Unknown,
        };

        self.emit_abc(opcode, left_reg, left_reg, right_reg)?;
        self.set_reg_type(left_reg, result_type)?;
        self.free_reg(right_reg)?;
        Ok(left_reg)
    }

    fn compile_and(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError> {
        let left_reg = self.compile_expr(lhs)?;

        // Short-circuit: if left is false, skip right
        let jump_end = self.emit_jump(OpCode::JumpIfFalse, left_reg)?;

        let right_reg = self.compile_expr(rhs)?;
        self.emit_abc(OpCode::Move, left_reg, right_reg, 0)?;
        self.free_reg(right_reg)?;

        self.patch_jump(jump_end)?;

        Ok(left_reg)
    }

    fn compile_or(&mut self, lhs: &Expr, rhs: &Expr) -> Result<u8, CompilerError> {
        let left_reg = self.compile_expr(lhs)?;

        // Short-circuit: if left is true, skip right
        let skip_jump = self.emit_jump(OpCode::JumpIfFalse, left_reg)?;
        let end_jump = self.emit_jump(OpCode::Jump, 0)?;
        self.patch_jump(skip_jump)?;

        let right_reg = self.compile_expr(rhs)?;
        self.emit_abc(OpCode::Move, left_reg, right_reg, 0)?;
        self.free_reg(right_reg)?;

        self.patch_jump(end_jump)?;

        Ok(left_reg)
    }
}
