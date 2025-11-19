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

    /// Compile match expression
    pub(crate) fn compile_match(
        &mut self,
        value: &AstNode,
        arms: &[achronyme_parser::ast::MatchArm],
    ) -> Result<RegResult, CompileError> {
        // Compile the value to match against
        let value_res = self.compile_expression(value)?;

        // Allocate result register (all arms will write here)
        let result_reg = self.registers.allocate()?;

        // Track jumps to end (from successful matches)
        let mut end_jumps = Vec::new();

        // Compile each match arm
        for arm in arms {
            // For each arm, we need to:
            // 1. Test the pattern
            // 2. If pattern matches AND guard passes (if present), execute body
            // 3. Otherwise, jump to next arm

            // Compile pattern matching
            match &arm.pattern {
                achronyme_parser::ast::Pattern::Wildcard => {
                    // Wildcard always matches, no test needed
                    // Compile guard if present
                    if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        let next_arm_jump = self.emit_jump_if_false(guard_res.reg(), 0);

                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }

                        // Guard passed, compile body
                        let body_res = self.compile_expression(&arm.body)?;
                        self.emit_move(result_reg, body_res.reg());

                        if body_res.is_temp() {
                            self.registers.free(body_res.reg());
                        }

                        // Jump to end
                        end_jumps.push(self.emit_jump(0));

                        // Patch jump to next arm
                        self.patch_jump(next_arm_jump);
                    } else {
                        // No guard, this is the final catch-all case
                        let body_res = self.compile_expression(&arm.body)?;
                        self.emit_move(result_reg, body_res.reg());

                        if body_res.is_temp() {
                            self.registers.free(body_res.reg());
                        }

                        // No need to jump, this is the last case
                        break;
                    }
                }

                achronyme_parser::ast::Pattern::Literal(lit) => {
                    // Compile literal pattern matching
                    let lit_value = match lit {
                        achronyme_parser::ast::LiteralPattern::Number(n) => crate::value::Value::Number(*n),
                        achronyme_parser::ast::LiteralPattern::Boolean(b) => crate::value::Value::Boolean(*b),
                        achronyme_parser::ast::LiteralPattern::String(s) => crate::value::Value::String(s.clone()),
                        achronyme_parser::ast::LiteralPattern::Null => crate::value::Value::Null,
                    };

                    let const_idx = self.add_constant(lit_value)?;
                    let match_reg = self.registers.allocate()?;

                    // Emit MatchLit: R[match_reg] = R[value] == K[const_idx]
                    self.emit(encode_abc(
                        OpCode::MatchLit.as_u8(),
                        match_reg,
                        value_res.reg(),
                        const_idx as u8,
                    ));

                    // Jump to next arm if pattern doesn't match
                    let next_arm_jump = self.emit_jump_if_false(match_reg, 0);
                    self.registers.free(match_reg);

                    // Pattern matched, check guard if present
                    let guard_jump = if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        let jump = self.emit_jump_if_false(guard_res.reg(), 0);

                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }
                        Some(jump)
                    } else {
                        None
                    };

                    // Pattern and guard passed, compile body
                    let body_res = self.compile_expression(&arm.body)?;
                    self.emit_move(result_reg, body_res.reg());

                    if body_res.is_temp() {
                        self.registers.free(body_res.reg());
                    }

                    // Jump to end
                    end_jumps.push(self.emit_jump(0));

                    // Patch jumps to next arm
                    self.patch_jump(next_arm_jump);
                    if let Some(guard_jump) = guard_jump {
                        self.patch_jump(guard_jump);
                    }
                }

                achronyme_parser::ast::Pattern::Type(type_name) => {
                    // Compile type pattern matching
                    let type_idx = self.add_string(type_name.clone())?;
                    let match_reg = self.registers.allocate()?;

                    // Emit MatchType: R[match_reg] = typeof(R[value]) == K[type_idx]
                    self.emit(encode_abc(
                        OpCode::MatchType.as_u8(),
                        match_reg,
                        value_res.reg(),
                        type_idx as u8,
                    ));

                    // Jump to next arm if pattern doesn't match
                    let next_arm_jump = self.emit_jump_if_false(match_reg, 0);
                    self.registers.free(match_reg);

                    // Pattern matched, check guard if present
                    let guard_jump = if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        let jump = self.emit_jump_if_false(guard_res.reg(), 0);

                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }
                        Some(jump)
                    } else {
                        None
                    };

                    // Pattern and guard passed, compile body
                    let body_res = self.compile_expression(&arm.body)?;
                    self.emit_move(result_reg, body_res.reg());

                    if body_res.is_temp() {
                        self.registers.free(body_res.reg());
                    }

                    // Jump to end
                    end_jumps.push(self.emit_jump(0));

                    // Patch jumps to next arm
                    self.patch_jump(next_arm_jump);
                    if let Some(guard_jump) = guard_jump {
                        self.patch_jump(guard_jump);
                    }
                }

                achronyme_parser::ast::Pattern::Variable(name) => {
                    // Variable pattern always matches and binds the value
                    // Allocate a register for the binding
                    let var_reg = self.registers.allocate()?;
                    self.emit_move(var_reg, value_res.reg());
                    self.symbols.define(name.clone(), var_reg)?;

                    // Check guard if present
                    let guard_jump = if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        let jump = self.emit_jump_if_false(guard_res.reg(), 0);

                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }
                        Some(jump)
                    } else {
                        None
                    };

                    // Compile body
                    let body_res = self.compile_expression(&arm.body)?;
                    self.emit_move(result_reg, body_res.reg());

                    if body_res.is_temp() {
                        self.registers.free(body_res.reg());
                    }

                    // Jump to end
                    end_jumps.push(self.emit_jump(0));

                    // Patch guard jump if present
                    if let Some(guard_jump) = guard_jump {
                        self.patch_jump(guard_jump);
                    }
                }

                achronyme_parser::ast::Pattern::Vector { .. } | achronyme_parser::ast::Pattern::Record { .. } => {
                    // For complex patterns (Vector/Record), we need to:
                    // 1. Destructure into temp registers
                    // 2. Check if destructuring succeeded (for now, assume it does)
                    // 3. Evaluate guard
                    // 4. Execute body

                    // This is simplified for Phase 4B - full implementation would need
                    // runtime checks for destructuring validity
                    return Err(CompileError::NotYetImplemented(
                        "Vector/Record patterns in match expressions".to_string()
                    ));
                }
            }
        }

        // Patch all end jumps
        for jump in end_jumps {
            self.patch_jump(jump);
        }

        // Free value register ONLY if temporary
        if value_res.is_temp() {
            self.registers.free(value_res.reg());
        }

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
