use std::collections::{HashMap, HashSet};

use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 9 — forward dataflow: no register read before it is written.
// Linear approximation; full dataflow analysis is future work.
// ---------------------------------------------------------------------

pub(super) fn check_forward_dataflow<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    let has_jumps = program
        .body
        .iter()
        .any(|i| matches!(i.opcode, Opcode::Jump { .. } | Opcode::JumpIf { .. }));
    if has_jumps {
        return Ok(()); // Full dataflow analysis is future work.
    }

    // Per-template-body initialized-register tracking. Key = template
    // id, or `None` for the top-level body. When a template body
    // first appears, its `n_params` capture registers (0..n_params)
    // are pre-initialized — the executor's `InstantiateTemplate`
    // handler populates them from the caller's `capture_regs` slice
    // before the body runs. The validator must mirror that contract;
    // otherwise any read from a capture-reg surfaces as a false
    // `UninitializedRegister` rule-9 violation. This matters most
    // post-Phase-4, when the walker emits hundreds of split-driven
    // templates whose first opcodes typically read from captures.
    let mut init: HashMap<Option<u16>, HashSet<u8>> = HashMap::new();
    init.insert(None, HashSet::new());

    for instr in &program.body {
        let host = hosting_template(program, instr.offset);
        let set = init.entry(host).or_insert_with(|| {
            let mut s = HashSet::new();
            if let Some(template_id) = host {
                if let Some(t) = program.templates.iter().find(|t| t.id == template_id) {
                    for i in 0..t.n_params {
                        s.insert(i);
                    }
                }
            }
            s
        });

        let reads = reads_of(&instr.opcode);
        let writes = writes_of(&instr.opcode);

        for r in reads {
            if !set.contains(&r) {
                return Err(LysisError::UninitializedRegister {
                    at_offset: instr.offset,
                    reg: r,
                });
            }
        }
        for w in writes {
            set.insert(w);
        }
    }
    Ok(())
}

pub(super) fn hosting_template<F: FieldBackend>(program: &Program<F>, offset: u32) -> Option<u16> {
    program
        .templates
        .iter()
        .find(|t| {
            let end = t.body_offset.saturating_add(t.body_len);
            offset >= t.body_offset && offset < end
        })
        .map(|t| t.id)
}

fn reads_of(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::JumpIf { cond, .. } => vec![*cond],
        Opcode::LoopRange { end_reg, .. } => vec![*end_reg],
        Opcode::InstantiateTemplate { capture_regs, .. } => capture_regs.as_ref().clone(),
        Opcode::TemplateOutput { src_reg, .. } => vec![*src_reg],
        Opcode::EmitConst { src_reg, .. } => vec![*src_reg],
        Opcode::EmitAdd { lhs, rhs, .. }
        | Opcode::EmitSub { lhs, rhs, .. }
        | Opcode::EmitMul { lhs, rhs, .. }
        | Opcode::EmitIsEq { lhs, rhs, .. }
        | Opcode::EmitIsLt { lhs, rhs, .. }
        | Opcode::EmitDiv { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitNeg { operand, .. } => vec![*operand],
        Opcode::EmitMux {
            cond,
            then_v,
            else_v,
            ..
        } => vec![*cond, *then_v, *else_v],
        Opcode::EmitDecompose { src, .. } => vec![*src],
        Opcode::EmitAssertEq { lhs, rhs } => vec![*lhs, *rhs],
        Opcode::EmitAssertEqMsg { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitRangeCheck { var, .. } => vec![*var],
        Opcode::EmitWitnessCall { in_regs, .. } => in_regs.as_ref().clone(),
        Opcode::EmitWitnessCallHeap { inputs, .. } => inputs
            .iter()
            .filter_map(|src| match src {
                crate::bytecode::opcode::InputSrc::Reg(r) => Some(*r),
                crate::bytecode::opcode::InputSrc::Slot(_) => None,
            })
            .collect(),
        Opcode::EmitPoseidonHash { in_regs, .. } => in_regs.as_ref().clone(),
        // StoreHeap reads its src_reg before writing it to the heap;
        // LoadHeap reads from the heap, not from regs (its read-side
        // is governed by Rules 12+13, not Rule 9).
        Opcode::StoreHeap { src_reg, .. } => vec![*src_reg],
        Opcode::EmitIntDiv { lhs, rhs, .. } | Opcode::EmitIntMod { lhs, rhs, .. } => {
            vec![*lhs, *rhs]
        }
        _ => Vec::new(),
    }
}

fn writes_of(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::LoadCapture { dst, .. }
        | Opcode::LoadConst { dst, .. }
        | Opcode::LoadInput { dst, .. }
        | Opcode::EmitConst { dst, .. }
        | Opcode::EmitAdd { dst, .. }
        | Opcode::EmitSub { dst, .. }
        | Opcode::EmitMul { dst, .. }
        | Opcode::EmitNeg { dst, .. }
        | Opcode::EmitMux { dst, .. }
        | Opcode::EmitPoseidonHash { dst, .. }
        | Opcode::EmitIsEq { dst, .. }
        | Opcode::EmitIsLt { dst, .. }
        | Opcode::EmitIntDiv { dst, .. }
        | Opcode::EmitIntMod { dst, .. }
        | Opcode::EmitDiv { dst, .. } => vec![*dst],
        Opcode::LoopUnroll { iter_var, .. }
        | Opcode::LoopRolled { iter_var, .. }
        | Opcode::LoopRange { iter_var, .. } => vec![*iter_var],
        Opcode::InstantiateTemplate { output_regs, .. } => output_regs.as_ref().clone(),
        Opcode::EmitDecompose {
            dst_arr, n_bits, ..
        } => (*dst_arr..dst_arr.saturating_add(*n_bits)).collect(),
        Opcode::EmitWitnessCall { out_regs, .. } => out_regs.as_ref().clone(),
        // LoadHeap materialises a heap entry into dst_reg — that's a
        // write from Rule 9's perspective. Without this, downstream
        // reads of the loaded reg fire false `UninitializedRegister`
        // errors.
        Opcode::LoadHeap { dst_reg, .. } => vec![*dst_reg],
        // EmitWitnessCallHeap outputs go to heap slots, not regs;
        // it writes nothing register-visible.
        _ => Vec::new(),
    }
}
