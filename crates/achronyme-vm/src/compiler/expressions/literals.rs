//! Literal expression compilation

use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::{AstNode, ArrayElement, RecordFieldOrSpread};
use achronyme_types::complex::Complex;

impl Compiler {
    /// Compile literal expressions
    pub(crate) fn compile_literal(
        &mut self,
        node: &AstNode,
    ) -> Result<RegResult, CompileError> {
        match node {
            AstNode::Number(n) => {
                let reg = self.registers.allocate()?;
                let const_idx = self.add_constant(Value::Number(*n))?;
                self.emit_load_const(reg, const_idx);
                Ok(RegResult::temp(reg))
            }

            AstNode::Boolean(b) => {
                let reg = self.registers.allocate()?;
                if *b {
                    self.emit(encode_abc(OpCode::LoadTrue.as_u8(), reg, 0, 0));
                } else {
                    self.emit(encode_abc(OpCode::LoadFalse.as_u8(), reg, 0, 0));
                }
                Ok(RegResult::temp(reg))
            }

            AstNode::Null => {
                let reg = self.registers.allocate()?;
                self.emit(encode_abc(OpCode::LoadNull.as_u8(), reg, 0, 0));
                Ok(RegResult::temp(reg))
            }

            AstNode::StringLiteral(s) => {
                let reg = self.registers.allocate()?;
                let const_idx = self.add_constant(Value::String(s.clone()))?;
                self.emit_load_const(reg, const_idx);
                Ok(RegResult::temp(reg))
            }

            AstNode::ComplexLiteral { re, im } => {
                let reg = self.registers.allocate()?;
                let complex = Complex::new(*re, *im);
                let const_idx = self.add_constant(Value::Complex(complex))?;
                self.emit_load_const(reg, const_idx);
                Ok(RegResult::temp(reg))
            }

            _ => unreachable!("Non-literal node in literal compiler"),
        }
    }

    /// Compile array literal using create-then-push strategy
    /// This avoids register exhaustion for large arrays
    pub(crate) fn compile_array_literal(
        &mut self,
        elements: &[ArrayElement],
    ) -> Result<RegResult, CompileError> {
        // Allocate register for the vector
        let vec_reg = self.registers.allocate()?;

        // Emit NewVector instruction
        self.emit(encode_abc(OpCode::NewVector.as_u8(), vec_reg, 0, 0));

        // Push each element one by one
        for element in elements {
            match element {
                ArrayElement::Single(node) => {
                    // Compile the element expression
                    let elem_res = self.compile_expression(node)?;

                    // Emit VecPush: vec_reg.push(elem_reg)
                    self.emit(encode_abc(
                        OpCode::VecPush.as_u8(),
                        vec_reg,
                        elem_res.reg(),
                        0,
                    ));

                    // Free temporary register
                    if elem_res.is_temp() {
                        self.registers.free(elem_res.reg());
                    }
                }
                ArrayElement::Spread(_spread_node) => {
                    // TODO: Implement spread operator for arrays
                    return Err(CompileError::Error(
                        "Spread operator in arrays not yet implemented".to_string(),
                    ));
                }
            }
        }

        Ok(RegResult::temp(vec_reg))
    }

    /// Compile record literal using create-then-set strategy
    pub(crate) fn compile_record_literal(
        &mut self,
        fields: &[RecordFieldOrSpread],
    ) -> Result<RegResult, CompileError> {
        // Allocate register for the record
        let rec_reg = self.registers.allocate()?;

        // Emit NewRecord instruction
        self.emit(encode_abc(OpCode::NewRecord.as_u8(), rec_reg, 0, 0));

        // Set each field one by one
        for field in fields {
            match field {
                RecordFieldOrSpread::Field { name, value } |
                RecordFieldOrSpread::MutableField { name, value } => {
                    // Compile the value expression
                    let val_res = self.compile_expression(value)?;

                    // Add field name to constant pool
                    let field_idx = self.add_string(name.clone())?;

                    // Emit SetField: rec_reg[field_name] = val_reg
                    self.emit(encode_abc(
                        OpCode::SetField.as_u8(),
                        rec_reg,
                        field_idx as u8,
                        val_res.reg(),
                    ));

                    // Free temporary register
                    if val_res.is_temp() {
                        self.registers.free(val_res.reg());
                    }
                }
                RecordFieldOrSpread::Spread(_spread_node) => {
                    // TODO: Implement spread operator for records
                    return Err(CompileError::Error(
                        "Spread operator in records not yet implemented".to_string(),
                    ));
                }
            }
        }

        Ok(RegResult::temp(rec_reg))
    }

    /// Compile range expression (0..5 or 0..=5)
    /// Ranges are expanded into vectors at compile time for simplicity
    pub(crate) fn compile_range(
        &mut self,
        start: &AstNode,
        end: &AstNode,
        inclusive: bool,
    ) -> Result<RegResult, CompileError> {
        use crate::value::Value;

        // Try to evaluate start and end as constants
        let start_val = match start {
            AstNode::Number(n) => *n,
            AstNode::UnaryOp { op: achronyme_parser::ast::UnaryOp::Negate, operand } => {
                match operand.as_ref() {
                    AstNode::Number(n) => -*n,
                    _ => return Err(CompileError::Error(
                        "Range start must be a number literal".to_string()
                    )),
                }
            }
            _ => return Err(CompileError::Error(
                "Range start must be a number literal".to_string()
            )),
        };

        let end_val = match end {
            AstNode::Number(n) => *n,
            AstNode::UnaryOp { op: achronyme_parser::ast::UnaryOp::Negate, operand } => {
                match operand.as_ref() {
                    AstNode::Number(n) => -*n,
                    _ => return Err(CompileError::Error(
                        "Range end must be a number literal".to_string()
                    )),
                }
            }
            _ => return Err(CompileError::Error(
                "Range end must be a number literal".to_string()
            )),
        };

        // Generate the range values
        let start_int = start_val as i64;
        let end_int = end_val as i64;

        // Create vector register
        let vec_reg = self.registers.allocate()?;

        // Emit NewVector instruction
        self.emit(encode_abc(OpCode::NewVector.as_u8(), vec_reg, 0, 0));

        // Push each value in the range
        let range_end = if inclusive { end_int + 1 } else { end_int };

        for i in start_int..range_end {
            // Load the number as a constant
            let val_reg = self.registers.allocate()?;
            let const_idx = self.add_constant(Value::Number(i as f64))?;
            self.emit_load_const(val_reg, const_idx);

            // Push to vector
            self.emit(encode_abc(
                OpCode::VecPush.as_u8(),
                vec_reg,
                val_reg,
                0,
            ));

            // Free temporary register
            self.registers.free(val_reg);
        }

        Ok(RegResult::temp(vec_reg))
    }
}
