use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 8 — register operand `r < frame_size`.
// Top-level frame_size is 256 (tautology for u8); template bodies use
// their declared frame_size.
// ---------------------------------------------------------------------

pub(super) fn check_register_bounds<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    for instr in &program.body {
        let frame_size = frame_size_at_offset(program, instr.offset);
        for reg in opcode_registers(&instr.opcode) {
            if (reg as u32) >= frame_size {
                return Err(LysisError::RegisterOutOfRange {
                    at_offset: instr.offset,
                    reg,
                    frame_size,
                });
            }
        }
    }
    Ok(())
}

/// The frame size active at the given offset. Returns 256 when the
/// offset does not fall inside any `DefineTemplate`-declared body.
fn frame_size_at_offset<F: FieldBackend>(program: &Program<F>, offset: u32) -> u32 {
    for t in &program.templates {
        let end = t.body_offset.saturating_add(t.body_len);
        if offset >= t.body_offset && offset < end {
            return t.frame_size as u32;
        }
    }
    256
}

/// Every register operand this opcode reads or writes. Used by the
/// register-bounds and forward-dataflow checks.
fn opcode_registers(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::LoadCapture { dst, .. }
        | Opcode::LoadConst { dst, .. }
        | Opcode::LoadInput { dst, .. } => vec![*dst],
        Opcode::EnterScope
        | Opcode::ExitScope
        | Opcode::Return
        | Opcode::Halt
        | Opcode::Trap { .. }
        | Opcode::Jump { .. } => Vec::new(),
        Opcode::JumpIf { cond, .. } => vec![*cond],
        Opcode::LoopUnroll { iter_var, .. } | Opcode::LoopRolled { iter_var, .. } => {
            vec![*iter_var]
        }
        Opcode::LoopRange {
            iter_var, end_reg, ..
        } => vec![*iter_var, *end_reg],
        Opcode::DefineTemplate { .. } => Vec::new(),
        Opcode::InstantiateTemplate {
            capture_regs,
            output_regs,
            ..
        } => {
            let mut v = capture_regs.as_ref().clone();
            v.extend_from_slice(output_regs);
            v
        }
        Opcode::TemplateOutput { src_reg, .. } => vec![*src_reg],
        Opcode::EmitConst { dst, src_reg } => vec![*dst, *src_reg],
        Opcode::EmitAdd { dst, lhs, rhs }
        | Opcode::EmitSub { dst, lhs, rhs }
        | Opcode::EmitMul { dst, lhs, rhs }
        | Opcode::EmitIsEq { dst, lhs, rhs }
        | Opcode::EmitIsLt { dst, lhs, rhs }
        | Opcode::EmitIsLtBounded { dst, lhs, rhs, .. }
        | Opcode::EmitDiv { dst, lhs, rhs } => vec![*dst, *lhs, *rhs],
        Opcode::EmitNeg { dst, operand } => vec![*dst, *operand],
        Opcode::EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => vec![*dst, *cond, *then_v, *else_v],
        Opcode::EmitDecompose { dst_arr, src, .. } => vec![*dst_arr, *src],
        Opcode::EmitAssertEq { lhs, rhs } => vec![*lhs, *rhs],
        Opcode::EmitAssertEqMsg { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitRangeCheck { var, .. } => vec![*var],
        Opcode::EmitWitnessCall {
            in_regs, out_regs, ..
        } => {
            let mut v = in_regs.as_ref().clone();
            v.extend_from_slice(out_regs);
            v
        }
        Opcode::EmitPoseidonHash { dst, in_regs } => {
            let mut v = vec![*dst];
            v.extend_from_slice(in_regs);
            v
        }
        Opcode::EmitIntDiv { dst, lhs, rhs, .. } | Opcode::EmitIntMod { dst, lhs, rhs, .. } => {
            vec![*dst, *lhs, *rhs]
        }
        Opcode::StoreHeap { src_reg, .. } => vec![*src_reg],
        Opcode::LoadHeap { dst_reg, .. } => vec![*dst_reg],
        // Outputs go to heap slots; inputs are mixed reg/slot.
        // Only `Reg(_)` inputs contribute to register-bounds checks.
        Opcode::EmitWitnessCallHeap { inputs, .. } => inputs
            .iter()
            .filter_map(|src| match src {
                crate::bytecode::opcode::InputSrc::Reg(r) => Some(*r),
                crate::bytecode::opcode::InputSrc::Slot(_) => None,
            })
            .collect(),
    }
}
