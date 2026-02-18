use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::control_flow::ControlFlowCompiler;
use achronyme_parser::Rule;
use pest::iterators::Pair;
use vm::opcode::OpCode;

pub trait BinaryCompiler {
    fn compile_binary(
        &mut self,
        pair: Pair<Rule>,
        op1: OpCode,
        op2: OpCode,
        is_right_associative: bool,
    ) -> Result<u8, CompilerError>;

    fn compile_comparison(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_and(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_or(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
}

impl BinaryCompiler for Compiler {
    // Handles logic for add_expr, mul_expr, pow_expr
    fn compile_binary(
        &mut self,
        pair: Pair<Rule>,
        op1: OpCode,
        op2: OpCode,
        is_right_associative: bool,
    ) -> Result<u8, CompilerError> {
        if is_right_associative {
            // Right-associative (e.g., Power: 2^3^2 = 2^(3^2))
            let mut pairs = pair.into_inner();
            let first_pair = pairs.next().unwrap();

            // 1. Collect all operands (registers)
            let mut regs = vec![self.compile_expr(first_pair)?];
            let mut ops = Vec::new();

            // 2. Collect all operators and subsequent operands
            while let Some(op_pair) = pairs.next() {
                let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;

                let opcode = match op_pair.as_str() {
                    "+" | "*" | "^" => op1,
                    "-" | "/" => op2,
                    "%" => OpCode::Mod,
                    _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
                };

                ops.push(opcode);
                regs.push(self.compile_expr(right_pair)?);
            }

            // 3. Fold Right-to-Left
            if ops.is_empty() {
                return Ok(regs[0]);
            }

            let mut right_reg = regs.pop().unwrap(); // Start with the last operand

            // Iterate backwards through operators
            while let Some(op) = ops.pop() {
                let left_reg = regs.pop().unwrap();
                // Reuse left_reg as result
                self.emit_abc(op, left_reg, left_reg, right_reg);
                self.free_reg(right_reg); // Hygiene
                right_reg = left_reg; // Result becomes the right operand for the next op
            }

            Ok(right_reg)
        } else {
            // Left-associative (Standard: 1-2-3 = (1-2)-3)
            let mut pairs = pair.into_inner();
            let left_reg = self.compile_expr(pairs.next().unwrap())?;

            while let Some(op_pair) = pairs.next() {
                let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
                let right_reg = self.compile_expr(right_pair)?;

                let opcode = match op_pair.as_str() {
                    "+" | "*" | "^" => op1,
                    "-" | "/" => op2,
                    "%" => OpCode::Mod,
                    _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
                };

                // REUSE left_reg as target (Accumulator pattern)
                self.emit_abc(opcode, left_reg, left_reg, right_reg);
                self.free_reg(right_reg); // Hygiene: Free the right operand (since it was just on top)
            }
            Ok(left_reg)
        }
    }

    fn compile_comparison(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut pairs = pair.into_inner();
        let left_reg = self.compile_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
            let right_reg = self.compile_expr(right_pair)?;

            let opcode = match op_pair.as_str() {
                "==" => OpCode::Eq,
                "!=" => OpCode::NotEq,
                "<" => OpCode::Lt,
                "<=" => OpCode::Le,
                ">" => OpCode::Gt,
                ">=" => OpCode::Ge,
                _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
            };

            // Reuse left_reg
            self.emit_abc(opcode, left_reg, left_reg, right_reg);
            self.free_reg(right_reg); // Hygiene
        }

        Ok(left_reg)
    }

    fn compile_and(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut pairs = pair.into_inner();
        let left_reg = self.compile_expr(pairs.next().unwrap())?;

        let mut end_jumps = Vec::new();

        while let Some(_op) = pairs.next() {
            // Short-circuit: if left is false, skip right
            let jump_idx = self.emit_jump(OpCode::JumpIfFalse, left_reg);
            end_jumps.push(jump_idx);

            let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
            let right_reg = self.compile_expr(right_pair)?;
            self.emit_abc(OpCode::Move, left_reg, right_reg, 0);
            self.free_reg(right_reg);
        }

        for j in end_jumps {
            self.patch_jump(j);
        }

        Ok(left_reg)
    }

    fn compile_or(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut pairs = pair.into_inner();
        let left_reg = self.compile_expr(pairs.next().unwrap())?;

        let mut end_jumps = Vec::new();

        while let Some(_op) = pairs.next() {
            // Short-circuit: if left is true, skip right
            // JumpIfFalse to continue; else jump to end
            let skip_jump = self.emit_jump(OpCode::JumpIfFalse, left_reg);
            let end_jump = self.emit_jump(OpCode::Jump, 0);
            end_jumps.push(end_jump);
            self.patch_jump(skip_jump);

            let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
            let right_reg = self.compile_expr(right_pair)?;
            self.emit_abc(OpCode::Move, left_reg, right_reg, 0);
            self.free_reg(right_reg);
        }

        for j in end_jumps {
            self.patch_jump(j);
        }

        Ok(left_reg)
    }
}
