//! Pattern compilation for destructuring and matching

use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::{LiteralPattern, Pattern, VectorPatternElement};

/// Pattern compilation mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PatternMode {
    /// Irrefutable pattern (let/mut binding) - must always match
    Irrefutable,
    /// Refutable pattern (match expression) - may fail to match
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
            Pattern::Literal(lit) => {
                self.compile_literal_pattern(lit, target_reg, mode)
            }

            Pattern::Variable(name) => {
                // Bind the target value to the variable name
                self.symbols.define(name.clone(), target_reg)?;
                Ok(())
            }

            Pattern::Wildcard => {
                // Wildcard matches anything, no code to emit
                Ok(())
            }

            Pattern::Vector { elements } => {
                self.compile_vector_pattern(elements, target_reg, mode)
            }

            Pattern::Record { fields } => {
                self.compile_record_pattern(fields, target_reg, mode)
            }

            Pattern::Type(type_name) => {
                self.compile_type_pattern(type_name, target_reg, mode)
            }
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
                    "Literal patterns are not allowed in irrefutable contexts (let bindings)".to_string()
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
                // Type patterns in irrefutable contexts don't make sense
                // because we can't guarantee the type at compile time
                Err(CompileError::InvalidPattern(
                    "Type patterns are not allowed in irrefutable contexts (let bindings)".to_string()
                ))
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
        let mut has_rest = false;

        for elem in elements {
            match elem {
                VectorPatternElement::Pattern(_, _) => element_count += 1,
                VectorPatternElement::Rest(_) => {
                    has_rest = true;
                    break; // Rest pattern must be last
                }
            }
        }

        if has_rest {
            return Err(CompileError::NotYetImplemented(
                "Rest patterns in vector destructuring".to_string()
            ));
        }

        // Create pattern descriptor (number of elements to extract)
        let pattern_desc = Value::Number(element_count as f64);
        let pattern_idx = self.add_constant(pattern_desc)?;

        // Allocate registers for extracted elements
        let dst_start = self.registers.allocate_many(element_count)?;

        // Emit DestructureVec instruction
        self.emit(encode_abc(
            OpCode::DestructureVec.as_u8(),
            dst_start,
            target_reg,
            pattern_idx as u8,
        ));

        // Now bind the pattern variables to the extracted values
        let mut reg_idx = dst_start;
        for elem in elements {
            match elem {
                VectorPatternElement::Pattern(pattern, default_value) => {
                    if default_value.is_some() {
                        return Err(CompileError::NotYetImplemented(
                            "Default values in vector patterns".to_string()
                        ));
                    }

                    // Recursively compile the nested pattern
                    self.compile_pattern(pattern, reg_idx, PatternMode::Irrefutable)?;
                    reg_idx += 1;
                }
                VectorPatternElement::Rest(_) => {
                    // Already handled above
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
        for (field_name, _, default_value) in fields {
            if default_value.is_some() {
                return Err(CompileError::NotYetImplemented(
                    "Default values in record patterns".to_string()
                ));
            }
            field_names.push(Value::String(field_name.clone()));
        }

        // Create pattern descriptor as a vector of field names
        let pattern_desc = Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(field_names)));
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
        for (_, pattern, _) in fields {
            // Recursively compile the nested pattern
            self.compile_pattern(pattern, reg_idx, PatternMode::Irrefutable)?;
            reg_idx += 1;
        }

        Ok(())
    }
}
