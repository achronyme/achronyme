//! Pattern compilation for destructuring and matching

use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::{LiteralPattern, Pattern, VectorPatternElement};
use achronyme_types::sync::shared;

/// Pattern compilation mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PatternMode {
    /// Irrefutable pattern (let/mut binding) - must always match
    Irrefutable,
    /// Refutable pattern (match expression) - may fail to match
    #[allow(dead_code)]
    Refutable,
}

impl Compiler {
    /// Compile a pattern for destructuring or matching
    ///
    /// # Arguments
    /// * `pattern` - The pattern AST node
    /// * `target_reg` - Register containing the value to match/destructure
    /// * `mode` - Compilation mode (irrefutable for let, refutable for match)
    /// * `result_reg` - Optional register to store boolean match result (only for Refutable mode)
    ///
    /// # Returns
    /// For Irrefutable mode: Ok(()) if compilation succeeds, Err if pattern is invalid
    /// For Refutable mode: Ok(()) and emits code that sets result_reg to true/false
    pub(crate) fn compile_pattern(
        &mut self,
        pattern: &Pattern,
        target_reg: u8,
        mode: PatternMode,
    ) -> Result<(), CompileError> {
        match pattern {
            Pattern::Literal(lit) => self.compile_literal_pattern(lit, target_reg, mode),

            Pattern::Variable(name) => {
                // Bind the target value to the variable name
                self.symbols.define(name.clone(), target_reg)?;
                Ok(())
            }

            Pattern::Wildcard => {
                // Wildcard matches anything, no code to emit
                Ok(())
            }

            Pattern::Vector { elements } => self.compile_vector_pattern(elements, target_reg, mode),

            Pattern::Record { fields } => self.compile_record_pattern(fields, target_reg, mode),

            Pattern::Type(type_name) => self.compile_type_pattern(type_name, target_reg, mode),
        }
    }

    /// Compile a literal pattern (matches exact values)
    fn compile_literal_pattern(
        &mut self,
        literal: &LiteralPattern,
        target_reg: u8,
        mode: PatternMode,
    ) -> Result<(), CompileError> {
        // Convert literal to Value and add to constant pool
        let const_value = match literal {
            LiteralPattern::Number(n) => Value::Number(*n),
            LiteralPattern::String(s) => Value::String(s.clone()),
            LiteralPattern::Boolean(b) => Value::Boolean(*b),
            LiteralPattern::Null => Value::Null,
        };

        let const_idx = self.add_constant(const_value)?;

        match mode {
            PatternMode::Irrefutable => {
                // For irrefutable patterns, we don't emit runtime checks
                // The semantics assume the pattern always matches
                // This is used in let bindings like: let 42 = x (which would be a type error)
                Err(CompileError::InvalidPattern(
                    "Literal patterns are not allowed in irrefutable contexts (let bindings)"
                        .to_string(),
                ))
            }
            PatternMode::Refutable => {
                // Emit MatchLit instruction: R[result] = R[target] == K[const_idx]
                let result_reg = self.registers.allocate()?;
                self.emit(encode_abc(
                    OpCode::MatchLit.as_u8(),
                    result_reg,
                    target_reg,
                    const_idx as u8,
                ));
                Ok(())
            }
        }
    }

    /// Compile a type pattern (matches by type name)
    fn compile_type_pattern(
        &mut self,
        type_name: &str,
        target_reg: u8,
        mode: PatternMode,
    ) -> Result<(), CompileError> {
        // Add type name to string constant pool
        let type_idx = self.add_string(type_name.to_string())?;

        match mode {
            PatternMode::Irrefutable => {
                // In irrefutable contexts (let bindings), type patterns act as runtime type checks
                // If the type doesn't match, we throw an error at runtime
                // This matches the tree-walker behavior

                // Emit MatchType instruction: R[result] = typeof(R[target]) == K[type_idx]
                let result_reg = self.registers.allocate()?;
                self.emit(encode_abc(
                    OpCode::MatchType.as_u8(),
                    result_reg,
                    target_reg,
                    type_idx as u8,
                ));

                // Check if type matches, throw error if not
                // We use JumpIfTrue to skip the error if type matches
                let skip_error = self.emit_jump_if_true(result_reg, 0);

                // Type doesn't match - throw error
                // Create error message as a string constant
                let error_msg = format!("Type mismatch: expected {}", type_name);
                let error_idx = self.add_constant(crate::value::Value::String(error_msg))?;
                let error_reg = self.registers.allocate()?;
                self.emit_load_const(error_reg, error_idx);
                self.emit(encode_abc(OpCode::Throw.as_u8(), error_reg, 0, 0));
                self.registers.free(error_reg);

                // Patch the skip jump
                self.patch_jump(skip_error);

                // Free the result register
                self.registers.free(result_reg);

                Ok(())
            }
            PatternMode::Refutable => {
                // Emit MatchType instruction: R[result] = typeof(R[target]) == K[type_idx]
                let result_reg = self.registers.allocate()?;
                self.emit(encode_abc(
                    OpCode::MatchType.as_u8(),
                    result_reg,
                    target_reg,
                    type_idx as u8,
                ));
                Ok(())
            }
        }
    }

    /// Compile a vector destructuring pattern
    fn compile_vector_pattern(
        &mut self,
        elements: &[VectorPatternElement],
        target_reg: u8,
        _mode: PatternMode,
    ) -> Result<(), CompileError> {
        // Count regular pattern elements (not rest patterns)
        let mut element_count = 0;
        let mut rest_name: Option<&String> = None;

        for elem in elements.iter() {
            match elem {
                VectorPatternElement::Pattern(_, _) => element_count += 1,
                VectorPatternElement::Rest(name) => {
                    rest_name = Some(name);
                    break; // Rest pattern must be last
                }
            }
        }

        // Create pattern descriptor (number of elements to extract)
        let pattern_desc = Value::Number(element_count as f64);
        let pattern_idx = self.add_constant(pattern_desc)?;

        // Allocate registers for extracted elements
        let mut registers_to_allocate = element_count;
        if rest_name.is_some() {
            registers_to_allocate += 1; // +1 for the rest vector
        }
        let dst_start = self.registers.allocate_many(registers_to_allocate)?;

        // Emit DestructureVec instruction for regular elements
        self.emit(encode_abc(
            OpCode::DestructureVec.as_u8(),
            dst_start,
            target_reg,
            pattern_idx as u8,
        ));

        // Now bind the pattern variables to the extracted values
        let mut reg_idx = dst_start;
        for elem in elements.iter() {
            match elem {
                VectorPatternElement::Pattern(pattern, default_value) => {
                    // If there's a default value, we need to handle the case where
                    // the vector is too short and the element doesn't exist
                    if let Some(default_expr) = default_value {
                        // Strategy: Check if we successfully extracted this element
                        // DestructureVec will have put something in the register
                        // We rely on the runtime to handle out-of-bounds gracefully
                        // For now, we'll use a simpler approach: unconditionally use the extracted value
                        // TODO: In a future version, check vector length and conditionally use default

                        // For Phase 4D, we'll implement a simplified version:
                        // If the pattern variable is meant to bind to a value that might not exist,
                        // we check if the register contains null and use default if so

                        // Compile the default value expression
                        let default_res = self.compile_expression(default_expr)?;

                        // Check if extracted value is null (simplified approach)
                        // JumpIfNull: if R[reg_idx] is null, use default, otherwise keep extracted value
                        let use_default_jump = self.emit_jump_if_null(reg_idx, 0);

                        // Value exists, skip default assignment
                        let skip_default_jump = self.emit_jump(0);

                        // Patch use_default_jump to here
                        self.patch_jump(use_default_jump);

                        // Use default value
                        self.emit_move(reg_idx, default_res.reg());
                        if default_res.is_temp() {
                            self.registers.free(default_res.reg());
                        }

                        // Patch skip_default_jump
                        self.patch_jump(skip_default_jump);
                    }

                    // Recursively compile the nested pattern
                    self.compile_pattern(pattern, reg_idx, PatternMode::Irrefutable)?;
                    reg_idx += 1;
                }
                VectorPatternElement::Rest(name) => {
                    // Handle rest pattern: create a slice from element_count to end
                    // R[rest_reg] = R[target_reg][element_count..end]
                    let rest_reg = reg_idx;

                    // Allocate TWO registers for slice range (start, end)
                    // VecSlice opcode uses R[C] for start and R[C+1] for end
                    let range_start_reg = self.registers.allocate_many(2)?;
                    let range_end_reg = range_start_reg + 1;

                    // Load start index (element_count)
                    let start_idx = Value::Number(element_count as f64);
                    let start_idx_const = self.add_constant(start_idx)?;
                    self.emit(encode_abx(
                        OpCode::LoadConst.as_u8(),
                        range_start_reg,
                        start_idx_const as u16,
                    ));

                    // Load end index (Null = end of vector)
                    self.emit(encode_abx(
                        OpCode::LoadNull.as_u8(),
                        range_end_reg,
                        0, // No operand for LoadNull
                    ));

                    // Emit VecSlice: R[rest_reg] = R[target_reg][start_reg..end_reg]
                    self.emit(encode_abc(
                        OpCode::VecSlice.as_u8(),
                        rest_reg,
                        target_reg,
                        range_start_reg,
                    ));

                    // Free the temp range registers
                    self.registers.free(range_end_reg);
                    self.registers.free(range_start_reg);

                    // Bind the rest variable
                    self.symbols.define(name.clone(), rest_reg)?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Compile a record destructuring pattern
    fn compile_record_pattern(
        &mut self,
        fields: &[(String, Pattern, Option<Box<achronyme_parser::ast::AstNode>>)],
        target_reg: u8,
        _mode: PatternMode,
    ) -> Result<(), CompileError> {
        // Extract field names and create pattern descriptor
        let mut field_names = Vec::new();
        for (field_name, _, _) in fields {
            field_names.push(Value::String(field_name.clone()));
        }

        // Create pattern descriptor as a vector of field names
        // Use shared() helper to create Shared<Vec<Value>>
        let pattern_desc = Value::Vector(shared(field_names));
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

        // Now bind the pattern variables to the extracted values
        let mut reg_idx = dst_start;
        for (field_name, pattern, default_value) in fields {
            // If there's a default value, handle missing fields
            if let Some(default_expr) = default_value {
                // Compile the default value expression
                let default_res = self.compile_expression(default_expr)?;

                // Check if extracted value is null (field doesn't exist)
                let use_default_jump = self.emit_jump_if_null(reg_idx, 0);

                // Value exists, skip default assignment
                let skip_default_jump = self.emit_jump(0);

                // Patch use_default_jump to here
                self.patch_jump(use_default_jump);

                // Use default value
                self.emit_move(reg_idx, default_res.reg());
                if default_res.is_temp() {
                    self.registers.free(default_res.reg());
                }

                // Patch skip_default_jump
                self.patch_jump(skip_default_jump);
            }

            // Recursively compile the nested pattern
            self.compile_pattern(pattern, reg_idx, PatternMode::Irrefutable)?;

            // Check if this is a non-binding pattern (Type, Wildcard, Literal)
            // In that case, we need to bind the field name to the value
            let needs_field_binding = matches!(
                pattern,
                Pattern::Type(_) | Pattern::Wildcard | Pattern::Literal(_)
            );
            if needs_field_binding {
                // Bind the field name to the extracted value
                self.symbols.define(field_name.clone(), reg_idx)?;
            }

            reg_idx += 1;
        }

        Ok(())
    }
}
