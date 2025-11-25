//! Control flow expression compilation (if, while)

use crate::compiler::context::LoopContext;
use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;
use achronyme_types::sync::shared;

impl Compiler {
    /// Compile a pattern for match expressions (refutable context)
    /// This handles nested patterns with literals/types by emitting match checks
    /// and collecting jump instructions to the next arm on failure
    fn compile_pattern_for_match(
        &mut self,
        pattern: &achronyme_parser::ast::Pattern,
        target_reg: u8,
        next_arm_jumps: &mut Vec<usize>,
    ) -> Result<(), CompileError> {
        use achronyme_parser::ast::{Pattern, VectorPatternElement};

        match pattern {
            Pattern::Literal(lit) => {
                // For literals in match context, emit a match check
                let lit_value = match lit {
                    achronyme_parser::ast::LiteralPattern::Number(n) => {
                        crate::value::Value::Number(*n)
                    }
                    achronyme_parser::ast::LiteralPattern::Boolean(b) => {
                        crate::value::Value::Boolean(*b)
                    }
                    achronyme_parser::ast::LiteralPattern::String(s) => {
                        crate::value::Value::String(s.clone())
                    }
                    achronyme_parser::ast::LiteralPattern::Null => crate::value::Value::Null,
                };

                let const_idx = self.add_constant(lit_value)?;
                let match_reg = self.registers.allocate()?;

                // Emit MatchLit: R[match_reg] = R[target] == K[const_idx]
                self.emit(encode_abc(
                    OpCode::MatchLit.as_u8(),
                    match_reg,
                    target_reg,
                    const_idx as u8,
                ));

                // Jump to next arm if pattern doesn't match
                next_arm_jumps.push(self.emit_jump_if_false(match_reg, 0));
                self.registers.free(match_reg);

                Ok(())
            }

            Pattern::Variable(name) => {
                // Variable pattern always matches and binds the value
                self.symbols.define(name.clone(), target_reg)?;
                Ok(())
            }

            Pattern::Wildcard => {
                // Wildcard always matches
                Ok(())
            }

            Pattern::Type(type_name) => {
                // Type pattern: check if value has the expected type
                let type_idx = self.add_string(type_name.clone())?;
                let match_reg = self.registers.allocate()?;

                self.emit(encode_abc(
                    OpCode::MatchType.as_u8(),
                    match_reg,
                    target_reg,
                    type_idx as u8,
                ));

                // Jump to next arm if type doesn't match
                next_arm_jumps.push(self.emit_jump_if_false(match_reg, 0));
                self.registers.free(match_reg);

                Ok(())
            }

            Pattern::Vector { elements } => {
                // Handle empty vector pattern []
                if elements.is_empty() {
                    // TODO: Implement proper length checking for empty vector patterns []
                    // For now, empty vector patterns match all vectors (known limitation)
                    // This is because:
                    // 1. DestructureVec doesn't validate length
                    // 2. There's no VecLen opcode to check length directly
                    // 3. GetGlobal isn't implemented to call len() function
                    // Workaround: Use guards like `if (len(x) == 0)` instead of `[]` pattern
                    return Ok(());
                }

                // Destructure vector and check nested patterns
                let element_count = elements
                    .iter()
                    .filter(|e| matches!(e, VectorPatternElement::Pattern(..)))
                    .count();
                let has_rest = elements
                    .iter()
                    .any(|e| matches!(e, VectorPatternElement::Rest(_)));

                // Create pattern descriptor
                let pattern_desc = crate::value::Value::Number(element_count as f64);
                let pattern_idx = self.add_constant(pattern_desc)?;

                // Allocate registers for extracted elements
                let mut registers_to_allocate = element_count;
                if has_rest {
                    registers_to_allocate += 1;
                }

                // Handle case where we need 0 registers
                if registers_to_allocate == 0 {
                    return Ok(());
                }

                let dst_start = self.registers.allocate_many(registers_to_allocate)?;

                // Emit DestructureVec instruction
                self.emit(encode_abc(
                    OpCode::DestructureVec.as_u8(),
                    dst_start,
                    target_reg,
                    pattern_idx as u8,
                ));

                // Now check nested patterns
                let mut reg_idx = dst_start;
                for elem in elements.iter() {
                    match elem {
                        VectorPatternElement::Pattern(nested_pattern, _default) => {
                            // Recursively compile nested pattern
                            self.compile_pattern_for_match(
                                nested_pattern,
                                reg_idx,
                                next_arm_jumps,
                            )?;
                            reg_idx += 1;
                        }
                        VectorPatternElement::Rest(name) => {
                            // Bind rest variable
                            let rest_reg = reg_idx;

                            // Load start index
                            let start_idx = crate::value::Value::Number(element_count as f64);
                            let start_idx_const = self.add_constant(start_idx)?;
                            let start_reg = self.registers.allocate()?;
                            self.emit(encode_abx(
                                OpCode::LoadConst.as_u8(),
                                start_reg,
                                start_idx_const as u16,
                            ));

                            // Emit VecSlice
                            self.emit(encode_abc(
                                OpCode::VecSlice.as_u8(),
                                rest_reg,
                                target_reg,
                                start_reg,
                            ));

                            self.registers.free(start_reg);
                            self.symbols.define(name.clone(), rest_reg)?;
                            break;
                        }
                    }
                }

                Ok(())
            }

            Pattern::Record { fields } => {
                // Destructure record and check nested patterns
                let mut field_names = Vec::new();
                for (field_name, _, _) in fields {
                    field_names.push(crate::value::Value::String(field_name.clone()));
                }

                // Create pattern descriptor
                let pattern_desc = crate::value::Value::Vector(shared(field_names));
                let pattern_idx = self.add_constant(pattern_desc)?;

                // Allocate registers for extracted fields
                let field_count = fields.len();
                let dst_start = self.registers.allocate_many(field_count)?;

                // Emit DestructureRec instruction
                self.emit(encode_abc(
                    OpCode::DestructureRec.as_u8(),
                    dst_start,
                    target_reg,
                    pattern_idx as u8,
                ));

                // Now check nested patterns and field existence
                let mut reg_idx = dst_start;
                for (field_name, nested_pattern, default_value) in fields {
                    // If there's no default value, the field must exist (not be null)
                    // Skip this check if the nested pattern is explicitly checking for null
                    let is_null_pattern = matches!(
                        nested_pattern,
                        Pattern::Literal(achronyme_parser::ast::LiteralPattern::Null)
                    );

                    if default_value.is_none() && !is_null_pattern {
                        // Check that the extracted field is not null
                        // If it is null, jump to next arm (field doesn't exist)
                        let null_check_reg = self.registers.allocate()?;
                        self.emit(encode_abc(OpCode::LoadNull.as_u8(), null_check_reg, 0, 0));

                        let eq_reg = self.registers.allocate()?;
                        self.emit(encode_abc(
                            OpCode::Eq.as_u8(),
                            eq_reg,
                            reg_idx,
                            null_check_reg,
                        ));

                        self.registers.free(null_check_reg);

                        // If field is null (equals null), jump to next arm
                        next_arm_jumps.push(self.emit_jump_if_true(eq_reg, 0));
                        self.registers.free(eq_reg);
                    }

                    // Recursively compile nested pattern
                    self.compile_pattern_for_match(nested_pattern, reg_idx, next_arm_jumps)?;

                    // If pattern is non-binding (Type, Wildcard, Literal), bind field name
                    let needs_field_binding = matches!(
                        nested_pattern,
                        Pattern::Type(_) | Pattern::Wildcard | Pattern::Literal(_)
                    );
                    if needs_field_binding {
                        self.symbols.define(field_name.clone(), reg_idx)?;
                    }

                    reg_idx += 1;
                }

                Ok(())
            }
        }
    }

    /// Compile if expression (default: not in tail position)
    #[allow(dead_code)]
    pub(crate) fn compile_if(
        &mut self,
        condition: &AstNode,
        then_expr: &AstNode,
        else_expr: Option<&AstNode>,
    ) -> Result<RegResult, CompileError> {
        self.compile_if_with_tail(condition, then_expr, else_expr, false)
    }

    /// Compile if expression with tail position awareness
    pub(crate) fn compile_if_with_tail(
        &mut self,
        condition: &AstNode,
        then_expr: &AstNode,
        else_expr: Option<&AstNode>,
        is_tail: bool,
    ) -> Result<RegResult, CompileError> {
        // Compile condition
        let cond_res = self.compile_expression(condition)?;

        // Jump to else if false
        let else_jump = self.emit_jump_if_false(cond_res.reg(), 0);

        // Free condition ONLY if temporary
        if cond_res.is_temp() {
            self.registers.free(cond_res.reg());
        }

        // Special handling for tail position
        if is_tail {
            // In tail position, branches must either:
            // 1. Do a TailCall (which acts as implicit return), or
            // 2. Explicitly return a value

            // Compile then branch (inherits tail position)
            let then_res = self.compile_expression_with_tail(then_expr, is_tail)?;
            // If the then branch didn't do a TailCall, we need to explicitly return
            // We need to emit a Return instruction
            self.emit(encode_abc(OpCode::Return.as_u8(), then_res.reg(), 0, 0));
            if then_res.is_temp() {
                self.registers.free(then_res.reg());
            }

            // Jump over else
            let end_jump = self.emit_jump(0);

            // Patch else jump
            self.patch_jump(else_jump);

            // Compile else branch (inherits tail position)
            if let Some(else_node) = else_expr {
                let else_res = self.compile_expression_with_tail(else_node, is_tail)?;
                // If the else branch didn't do a TailCall, we need to explicitly return
                self.emit(encode_abc(OpCode::Return.as_u8(), else_res.reg(), 0, 0));
                if else_res.is_temp() {
                    self.registers.free(else_res.reg());
                }
            } else {
                // No else branch, return null
                let null_reg = self.registers.allocate()?;
                self.emit(encode_abc(OpCode::LoadNull.as_u8(), null_reg, 0, 0));
                self.emit(encode_abc(OpCode::Return.as_u8(), null_reg, 0, 0));
                self.registers.free(null_reg);
            }

            // Patch end jump
            self.patch_jump(end_jump);

            // Return a dummy register (will never be used since we returned)
            Ok(RegResult::temp(0))
        } else {
            // Non-tail position: normal if-else with result register
            // Compile then branch
            let then_res = self.compile_expression_with_tail(then_expr, is_tail)?;
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
                let else_res = self.compile_expression_with_tail(else_node, is_tail)?;
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
                        achronyme_parser::ast::LiteralPattern::Number(n) => {
                            crate::value::Value::Number(*n)
                        }
                        achronyme_parser::ast::LiteralPattern::Boolean(b) => {
                            crate::value::Value::Boolean(*b)
                        }
                        achronyme_parser::ast::LiteralPattern::String(s) => {
                            crate::value::Value::String(s.clone())
                        }
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

                achronyme_parser::ast::Pattern::Vector { elements } => {
                    // For vector patterns in match expressions:
                    // 1. Check if value is a vector type
                    // 2. Destructure and bind variables
                    // 3. Check nested patterns (literals, types, etc.)
                    // 4. Evaluate guard if present
                    // 5. Execute body

                    // Check if the value is a vector type
                    let type_idx = self.add_string("Vector".to_string())?;
                    let type_check_reg = self.registers.allocate()?;
                    self.emit(encode_abc(
                        OpCode::MatchType.as_u8(),
                        type_check_reg,
                        value_res.reg(),
                        type_idx as u8,
                    ));

                    // Jump to next arm if not a vector
                    let mut next_arm_jumps = vec![self.emit_jump_if_false(type_check_reg, 0)];
                    self.registers.free(type_check_reg);

                    // Destructure the vector (this binds variables)
                    // For now, we use Irrefutable mode and rely on runtime checks
                    // TODO: Implement proper refutable pattern compilation with match result
                    self.compile_pattern_for_match(
                        &achronyme_parser::ast::Pattern::Vector {
                            elements: elements.clone(),
                        },
                        value_res.reg(),
                        &mut next_arm_jumps,
                    )?;

                    // Check guard if present
                    if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        next_arm_jumps.push(self.emit_jump_if_false(guard_res.reg(), 0));
                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }
                    }

                    // Compile body
                    let body_res = self.compile_expression(&arm.body)?;
                    self.emit_move(result_reg, body_res.reg());
                    if body_res.is_temp() {
                        self.registers.free(body_res.reg());
                    }

                    // Jump to end
                    end_jumps.push(self.emit_jump(0));

                    // Patch all jumps to next arm
                    for jump in next_arm_jumps {
                        self.patch_jump(jump);
                    }
                }

                achronyme_parser::ast::Pattern::Record { fields } => {
                    // For record patterns in match expressions:
                    // 1. Check if value is a record type
                    // 2. Destructure and bind variables
                    // 3. Check nested patterns (literals, types, etc.)
                    // 4. Evaluate guard if present
                    // 5. Execute body

                    // Check if the value is a record type
                    let type_idx = self.add_string("Record".to_string())?;
                    let type_check_reg = self.registers.allocate()?;
                    self.emit(encode_abc(
                        OpCode::MatchType.as_u8(),
                        type_check_reg,
                        value_res.reg(),
                        type_idx as u8,
                    ));

                    // Jump to next arm if not a record
                    let mut next_arm_jumps = vec![self.emit_jump_if_false(type_check_reg, 0)];
                    self.registers.free(type_check_reg);

                    // Destructure the record (this binds variables and checks nested patterns)
                    self.compile_pattern_for_match(
                        &achronyme_parser::ast::Pattern::Record {
                            fields: fields.clone(),
                        },
                        value_res.reg(),
                        &mut next_arm_jumps,
                    )?;

                    // Check guard if present
                    if let Some(guard) = &arm.guard {
                        let guard_res = self.compile_expression(guard)?;
                        next_arm_jumps.push(self.emit_jump_if_false(guard_res.reg(), 0));
                        if guard_res.is_temp() {
                            self.registers.free(guard_res.reg());
                        }
                    }

                    // Compile body
                    let body_res = self.compile_expression(&arm.body)?;
                    self.emit_move(result_reg, body_res.reg());
                    if body_res.is_temp() {
                        self.registers.free(body_res.reg());
                    }

                    // Jump to end
                    end_jumps.push(self.emit_jump(0));

                    // Patch all jumps to next arm
                    for jump in next_arm_jumps {
                        self.patch_jump(jump);
                    }
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
    pub(crate) fn compile_while(
        &mut self,
        condition: &AstNode,
        body: &AstNode,
    ) -> Result<RegResult, CompileError> {
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

    /// Compile for-in loop
    /// Desugars: for (x in iterable) { body }
    /// Into bytecode equivalent to:
    ///   let $iter = iterable
    ///   loop {
    ///     let $result = $iter.next()
    ///     let $done = $result.done
    ///     if ($done) { break }
    ///     let x = $result.value
    ///     body
    ///   }
    pub(crate) fn compile_for_in(
        &mut self,
        variable: &str,
        iterable: &AstNode,
        body: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Compile the iterable expression to get iterator
        let iter_res = self.compile_expression(iterable)?;
        let iter_src_reg = iter_res.reg();

        // Wrap the iterable in an iterator if needed (MakeIterator)
        // This normalizes generators, vectors, and strings into iterators
        let iter_reg = self.registers.allocate()?;
        self.emit(encode_abc(
            OpCode::MakeIterator.as_u8(),
            iter_reg,
            iter_src_reg,
            0,
        ));

        // Free the source register if it was temporary
        if iter_res.is_temp() {
            self.registers.free(iter_src_reg);
        }

        // Mark loop start
        let loop_start = self.current_position();

        // Call .next() on the iterator
        // Directly emit ResumeGen bytecode: R[result] = iter.next()
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(
            OpCode::ResumeGen.as_u8(),
            result_reg,
            iter_reg,
            0,
        ));

        // Extract the 'done' field: $result.done
        let done_reg = self.registers.allocate()?;
        let done_field_idx = self.add_string("done".to_string())?;
        self.emit(encode_abc(
            OpCode::GetField.as_u8(),
            done_reg,
            result_reg,
            done_field_idx as u8,
        ));

        // Jump to end if done is true
        let end_jump = self.emit_jump_if_true(done_reg, 0);

        // Free done register
        self.registers.free(done_reg);

        // Extract the 'value' field: $result.value
        let value_reg = self.registers.allocate()?;
        let value_field_idx = self.add_string("value".to_string())?;
        self.emit(encode_abc(
            OpCode::GetField.as_u8(),
            value_reg,
            result_reg,
            value_field_idx as u8,
        ));

        // Free result register (always temporary since we allocated it)
        self.registers.free(result_reg);

        // Bind the value to the loop variable
        // Allocate a register for the loop variable
        let var_reg = self.registers.allocate()?;
        self.emit_move(var_reg, value_reg);
        self.registers.free(value_reg);

        // Define the loop variable in the symbol table
        self.symbols.define(variable.to_string(), var_reg)?;

        // Push loop context
        self.loops.push(LoopContext {
            start: loop_start,
            breaks: Vec::new(),
        });

        // Compile body - handle both statements and expressions
        // Check if body is a statement (not an expression)
        let is_statement = matches!(
            body,
            AstNode::VariableDecl { .. }
                | AstNode::MutableDecl { .. }
                | AstNode::LetDestructuring { .. }
                | AstNode::MutableDestructuring { .. }
                | AstNode::Assignment { .. }
                | AstNode::Import { .. }
                | AstNode::Export { .. }
        );

        if is_statement {
            // Compile as statement
            self.compile_statement(body)?;
        } else {
            // Compile as expression
            let body_res = self.compile_expression(body)?;
            // Free body result if temporary
            if body_res.is_temp() {
                self.registers.free(body_res.reg());
            }
        }

        // Jump back to loop start
        let offset = -(self.current_position() as i16 - loop_start as i16 + 1);
        self.emit_jump(offset);

        // Patch end jump
        self.patch_jump(end_jump);

        // Pop loop context and patch breaks
        let loop_ctx = self.loops.pop().unwrap();
        for break_pos in loop_ctx.breaks {
            self.patch_jump(break_pos);
        }

        // Clean up: undefine the loop variable and $iter
        // Note: In a real implementation, we'd want proper scope management
        // For now, we just leave them in the symbol table

        // Free the iterator register (it's always temporary after MakeIterator)
        self.registers.free(iter_reg);

        // For-in loop returns null
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));

        Ok(RegResult::temp(result_reg))
    }

    /// Compile break statement
    pub(crate) fn compile_break(
        &mut self,
        value: Option<&AstNode>,
    ) -> Result<RegResult, CompileError> {
        // Check if we're inside a loop
        if self.loops.is_empty() {
            return Err(CompileError::Error(
                "break statement outside loop".to_string(),
            ));
        }

        // For now, ignore the optional value (break value feature)
        // Future enhancement: support break with value
        if value.is_some() {
            return Err(CompileError::NotYetImplemented(
                "break with value".to_string(),
            ));
        }

        // Emit jump to end of loop (will be patched later)
        let break_jump = self.emit_jump(0);

        // Add to current loop's break list
        let loop_ctx = self.loops.last_mut().unwrap();
        loop_ctx.breaks.push(break_jump);

        // Break doesn't return a value, return null
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));

        Ok(RegResult::temp(result_reg))
    }

    /// Compile continue statement
    pub(crate) fn compile_continue(&mut self) -> Result<RegResult, CompileError> {
        // Check if we're inside a loop
        if self.loops.is_empty() {
            return Err(CompileError::Error(
                "continue statement outside loop".to_string(),
            ));
        }

        // Get the loop start position
        let loop_ctx = self.loops.last().unwrap();
        let loop_start = loop_ctx.start;

        // Jump back to loop start
        let offset = -(self.current_position() as i16 - loop_start as i16 + 1);
        self.emit_jump(offset);

        // Continue doesn't return a value, return null
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));

        Ok(RegResult::temp(result_reg))
    }

    /// Compile try-catch expression
    /// Syntax: try { try_block } catch(error_param) { catch_block }
    /// Both try and catch blocks write to the same result register
    pub(crate) fn compile_try_catch(
        &mut self,
        try_block: &AstNode,
        error_param: &str,
        catch_block: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Allocate result register first (both branches write here)
        let result_reg = self.registers.allocate()?;

        // Allocate error register (will hold exception value in catch block)
        let err_reg = self.registers.allocate()?;

        // Emit PUSH_HANDLER (will patch offset later)
        // PUSH_HANDLER uses ABx format: A = error_reg, Bx = offset
        let push_pos = self.current_position();
        self.emit(encode_abx(OpCode::PushHandler.as_u8(), err_reg, 0));

        // Compile try block (result goes to result_reg)
        let try_res = self.compile_expression(try_block)?;
        if try_res.reg() != result_reg {
            self.emit_move(result_reg, try_res.reg());
        }
        if try_res.is_temp() && try_res.reg() != result_reg {
            self.registers.free(try_res.reg());
        }

        // Pop handler (try succeeded)
        self.emit(encode_abc(OpCode::PopHandler.as_u8(), 0, 0, 0));

        // Jump over catch block
        let jump_pos = self.current_position();
        self.emit_jump(0);

        // CATCH BLOCK STARTS HERE
        let catch_start = self.current_position();

        // Patch PUSH_HANDLER offset to point to catch block
        // Offset calculation: catch_start = push_pos + 1 + offset
        // So: offset = catch_start - push_pos - 1
        let offset = (catch_start - push_pos - 1) as u16;
        self.function.code[push_pos] = encode_abx(OpCode::PushHandler.as_u8(), err_reg, offset);

        // Define error variable (err_reg already has the error value from VM)
        // Note: This binding is local to the catch block, but we don't have explicit
        // scope management in the SymbolTable. The register will be reused after this block.
        self.symbols.define(error_param.to_string(), err_reg)?;

        // Compile catch block
        let catch_res = self.compile_expression(catch_block)?;
        if catch_res.reg() != result_reg {
            self.emit_move(result_reg, catch_res.reg());
        }
        if catch_res.is_temp() && catch_res.reg() != result_reg {
            self.registers.free(catch_res.reg());
        }

        // CATCH BLOCK ENDS HERE
        // Patch jump over catch block
        self.patch_jump(jump_pos);

        // Free error register
        self.registers.free(err_reg);

        Ok(RegResult::temp(result_reg))
    }

    /// Compile throw expression
    /// Syntax: throw value
    /// Throws an exception that can be caught by try-catch
    pub(crate) fn compile_throw(&mut self, value: &AstNode) -> Result<RegResult, CompileError> {
        // Compile the value to throw
        let val_res = self.compile_expression(value)?;

        // Emit THROW instruction
        self.emit(encode_abc(OpCode::Throw.as_u8(), val_res.reg(), 0, 0));

        // Free the value register if temporary
        if val_res.is_temp() {
            self.registers.free(val_res.reg());
        }

        // Throw never returns normally, but we need to return something for type checking
        // Allocate a dummy register with null value
        let dummy_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), dummy_reg, 0, 0));

        Ok(RegResult::temp(dummy_reg))
    }

    /// Compile return expression
    /// Syntax: return value
    /// Returns from the current function with the given value
    /// This is used when return appears in expression context (e.g., inside do blocks)
    pub(crate) fn compile_return_expr(
        &mut self,
        value: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Compile the value to return
        let value_res = self.compile_expression(value)?;

        // Emit RETURN instruction
        self.emit(encode_abc(OpCode::Return.as_u8(), value_res.reg(), 0, 0));

        // Free the value register if temporary
        if value_res.is_temp() {
            self.registers.free(value_res.reg());
        }

        // Return never returns normally, but we need to return something for type checking
        // Allocate a dummy register with null value (will never be used)
        let dummy_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), dummy_reg, 0, 0));

        Ok(RegResult::temp(dummy_reg))
    }
}
