use super::*;

impl<F: FieldBackend> Walker<F> {
    pub(super) fn emit(&mut self, inst: &ExtendedInstruction<F>) -> Result<(), WalkError> {
        match inst {
            ExtendedInstruction::Plain(i) => self.emit_plain(i),
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body,
            } => self.emit_loop_unroll(*iter_var, *start, *end, body),
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => self.emit_template_call(*template_id, captures, outputs),
            ExtendedInstruction::TemplateBody {
                id,
                frame_size,
                n_params,
                captures,
                body,
            } => self.emit_template_body(*id, *frame_size, *n_params, captures, body),
            ExtendedInstruction::SymbolicIndexedEffect {
                kind,
                array_slots,
                index_var,
                value_var,
                span: _,
            } => self.emit_symbolic_indexed_effect(*kind, array_slots, *index_var, *value_var),
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                span: _,
            } => self.emit_symbolic_array_read(*result_var, array_slots, *index_var),
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                num_bits,
                direction,
                span: _,
            } => self.emit_symbolic_shift(
                *result_var,
                *operand_var,
                *shift_var,
                *num_bits,
                *direction,
            ),
        }
    }
}
