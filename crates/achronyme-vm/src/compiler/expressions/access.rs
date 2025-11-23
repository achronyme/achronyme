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

        // Compile the object being indexed
        let obj_res = self.compile_expression(object)?;

        // Case 1: Single index (common for Vectors)
        if indices.len() == 1 {
            match &indices[0] {
                IndexArg::Single(idx_expr) => {
                    // Existing logic for single index: VecGet
                    let idx_res = self.compile_expression(idx_expr)?;
                    let result_reg = self.registers.allocate()?;
                    
                    // VecGet: R[result] = R[obj][R[idx]]
                    self.emit(encode_abc(
                        OpCode::VecGet.as_u8(),
                        result_reg,
                        obj_res.reg(),
                        idx_res.reg(),
                    ));

                    // Free temporary registers
                    if obj_res.is_temp() { self.registers.free(obj_res.reg()); }
                    if idx_res.is_temp() { self.registers.free(idx_res.reg()); }

                    return Ok(RegResult::temp(result_reg));
                }
                IndexArg::Range { start, end } => {
                    // Range slice: vec[start..end]
                    // Use VecSlice with 2 args (Start, End) for efficiency on 1D
                    let range_regs = self.registers.allocate_many(2)?;
                    let start_reg = range_regs;
                    let end_reg = range_regs + 1;

                    // Compile start
                    if let Some(s) = start {
                        let s_res = self.compile_expression(s)?;
                        self.emit_move(start_reg, s_res.reg());
                        if s_res.is_temp() { self.registers.free(s_res.reg()); }
                    } else {
                        self.emit(encode_abc(OpCode::LoadNull.as_u8(), start_reg, 0, 0));
                    }

                    // Compile end
                    if let Some(e) = end {
                        let e_res = self.compile_expression(e)?;
                        self.emit_move(end_reg, e_res.reg());
                        if e_res.is_temp() { self.registers.free(e_res.reg()); }
                    } else {
                        self.emit(encode_abc(OpCode::LoadNull.as_u8(), end_reg, 0, 0));
                    }

                    let result_reg = self.registers.allocate()?;
                    // VecSlice A=dest, B=obj, C=start_reg (end is implicitly C+1)
                    self.emit(encode_abc(
                        OpCode::VecSlice.as_u8(),
                        result_reg,
                        obj_res.reg(),
                        start_reg,
                    ));

                    // Free registers
                    self.registers.free(start_reg);
                    self.registers.free(end_reg);
                    if obj_res.is_temp() { self.registers.free(obj_res.reg()); }

                    return Ok(RegResult::temp(result_reg));
                }
            }
        }

        // Case 2: Multi-dimensional access (Tensor)
        // We use TensorGet with a variable argument list of indices
        
        // Allocate frame for Tensor + Indices
        // Frame: [Tensor, Index0, Index1, ...]
        let frame_start = self.registers.allocate_many(1 + indices.len())?;
        let tensor_slot = frame_start;
        let indices_start = frame_start + 1;

        // Move tensor to slot 0
        self.emit_move(tensor_slot, obj_res.reg());
        if obj_res.is_temp() { self.registers.free(obj_res.reg()); }

        // Compile/Move indices to slots 1..N
        for (i, arg) in indices.iter().enumerate() {
            let target_reg = indices_start + (i as u8);
            match arg {
                IndexArg::Single(expr) => {
                    let expr_res = self.compile_expression(expr)?;
                    self.emit_move(target_reg, expr_res.reg());
                    if expr_res.is_temp() { self.registers.free(expr_res.reg()); }
                }
                IndexArg::Range { start, end } => {
                    // Compile range into Value::Range using RangeEx opcode
                    // We need temporary registers for start/end
                    let range_inputs = self.registers.allocate_many(2)?;
                    let s_reg = range_inputs;
                    let e_reg = range_inputs + 1;

                    if let Some(s) = start {
                        let res = self.compile_expression(s)?;
                        self.emit_move(s_reg, res.reg());
                        if res.is_temp() { self.registers.free(res.reg()); }
                    } else {
                        self.emit(encode_abc(OpCode::LoadNull.as_u8(), s_reg, 0, 0));
                    }

                    if let Some(e) = end {
                        let res = self.compile_expression(e)?;
                        self.emit_move(e_reg, res.reg());
                        if res.is_temp() { self.registers.free(res.reg()); }
                    } else {
                        self.emit(encode_abc(OpCode::LoadNull.as_u8(), e_reg, 0, 0));
                    }

                    // Emit RangeEx: target_reg = s_reg..e_reg
                    self.emit(encode_abc(
                        OpCode::RangeEx.as_u8(),
                        target_reg,
                        s_reg,
                        e_reg,
                    ));

                    self.registers.free(s_reg);
                    self.registers.free(e_reg);
                }
            }
        }

        // Allocate result register
        let result_reg = self.registers.allocate()?;

        // Emit TensorGet: A=dest, B=base_reg (Tensor), C=count (Indices)
        // The VM reads Tensor from R[B], Indices from R[B+1]...R[B+C]
        self.emit(encode_abc(
            OpCode::TensorGet.as_u8(),
            result_reg,
            tensor_slot,
            indices.len() as u8,
        ));

        // Free frame registers
        for i in 0..=indices.len() {
            self.registers.free(frame_start + i as u8);
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
