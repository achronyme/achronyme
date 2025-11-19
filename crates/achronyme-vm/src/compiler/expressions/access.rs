//! Index and field access compilation

use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;

impl Compiler {
    /// Compile index access (e.g., arr[0])
    /// For reading: R[A] = R[B][R[C]]
    pub(crate) fn compile_index_access(
        &mut self,
        object: &AstNode,
        indices: &[achronyme_parser::ast::IndexArg],
    ) -> Result<RegResult, CompileError> {
        use achronyme_parser::ast::IndexArg;

        // For Phase 3, only support single index access
        if indices.len() != 1 {
            return Err(CompileError::Error(
                "Multi-dimensional indexing not yet supported".to_string(),
            ));
        }

        // Extract the single index
        let index_node = match &indices[0] {
            IndexArg::Single(node) => node,
            IndexArg::Range { .. } => {
                return Err(CompileError::Error(
                    "Range slicing not yet supported".to_string(),
                ));
            }
        };

        // Compile the object being indexed
        let obj_res = self.compile_expression(object)?;

        // Compile the index expression
        let idx_res = self.compile_expression(index_node)?;

        // Allocate result register
        let result_reg = self.registers.allocate()?;

        // Emit VecGet: R[result] = R[obj][R[idx]]
        self.emit(encode_abc(
            OpCode::VecGet.as_u8(),
            result_reg,
            obj_res.reg(),
            idx_res.reg(),
        ));

        // Free temporary registers
        if obj_res.is_temp() {
            self.registers.free(obj_res.reg());
        }
        if idx_res.is_temp() {
            self.registers.free(idx_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }

    /// Compile field access (e.g., obj.field)
    /// For reading: R[A] = R[B][K[C]]
    pub(crate) fn compile_field_access(
        &mut self,
        record: &AstNode,
        field: &str,
    ) -> Result<RegResult, CompileError> {
        // Compile the record being accessed
        let rec_res = self.compile_expression(record)?;

        // Add field name to constant pool
        let field_idx = self.add_string(field.to_string())?;

        // Allocate result register
        let result_reg = self.registers.allocate()?;

        // Emit GetField: R[result] = R[rec][K[field_idx]]
        self.emit(encode_abc(
            OpCode::GetField.as_u8(),
            result_reg,
            rec_res.reg(),
            field_idx as u8,
        ));

        // Free temporary register
        if rec_res.is_temp() {
            self.registers.free(rec_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }
}
