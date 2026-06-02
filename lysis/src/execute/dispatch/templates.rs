use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::intern::NodeId;

use super::super::frame::Frame;
use super::super::runtime::read_reg;
use super::super::step::Step;
use super::DispatchCtx;

pub(super) fn dispatch<F: FieldBackend, S: super::super::ir_sink::IrSink<F>>(
    opcode: &Opcode,
    ctx: &mut DispatchCtx<'_, F, S>,
) -> Result<Step, LysisError> {
    use Opcode::*;

    match opcode {
        DefineTemplate { .. } => {
            // Pure metadata: already harvested during decode. Skip.
            Ok(Step::Next)
        }
        InstantiateTemplate {
            template_id,
            capture_regs,
            output_regs,
        } => {
            let template = ctx
                .template_lookup
                .get(*template_id as usize)
                .and_then(|slot| *slot)
                .ok_or(LysisError::UndefinedTemplate {
                    at_offset: ctx.offset,
                    template_id: *template_id,
                })?;
            // Runtime rule-11 backstop.
            if (ctx.frames.len() as u32) >= ctx.config.max_call_depth {
                return Err(LysisError::CallStackOverflow {
                    depth: ctx.frames.len() as u32,
                    max: ctx.config.max_call_depth,
                });
            }
            let (body_start, body_end) = ctx
                .template_body_ranges
                .get(*template_id as usize)
                .and_then(|slot| *slot)
                .ok_or(LysisError::ValidationFailed {
                    rule: 7,
                    location: ctx.offset,
                    detail: "template body_offset does not resolve to an instruction index",
                })?;

            // Move captures from caller regs into new frame.
            let caller = &ctx.frames[ctx.frame_idx];
            let mut new_frame_regs: Vec<Option<NodeId>> = vec![None; template.frame_size as usize];
            for (i, cap_reg) in capture_regs.iter().enumerate() {
                if i >= new_frame_regs.len() {
                    break;
                }
                let val = read_reg(caller, *cap_reg, ctx.offset)?;
                new_frame_regs[i] = Some(val);
            }

            let new_frame = Frame {
                regs: new_frame_regs,
                pc: body_start,
                body_start_idx: body_start,
                body_end_idx: body_end,
                template_id: Some(*template_id),
                output_slots: vec![None; output_regs.len()],
                caller_output_regs: output_regs.as_ref().clone(),
                caller_frame_idx: Some(ctx.frame_idx),
                loop_stack: Vec::new(),
            };

            // Tail-call elimination. The caller has nothing left to do
            // after the callee returns iff the instruction right after
            // this `InstantiateTemplate` is `Return`, the caller is not
            // mid-loop-iteration, and there are no outputs to project
            // back (this call's `output_regs` and the caller's own
            // `caller_output_regs` are both empty). The walker's
            // split-chain (`InstantiateTemplate(next); Return`, empty
            // output_regs) satisfies this for every link, so the chain
            // runs in O(1) frames. Any other shape falls back to the
            // stack-growing push.
            let caller = &ctx.frames[ctx.frame_idx];
            let tail = output_regs.is_empty()
                && caller.caller_output_regs.is_empty()
                && caller.loop_stack.is_empty()
                && matches!(
                    ctx.program.body.get(caller.pc + 1).map(|i| &i.opcode),
                    Some(Opcode::Return)
                );
            if tail {
                Ok(Step::TailCall(new_frame))
            } else {
                Ok(Step::PushFrame(new_frame))
            }
        }
        TemplateOutput {
            output_idx,
            src_reg,
        } => {
            let frame = &mut ctx.frames[ctx.frame_idx];
            let val = frame
                .read(*src_reg)
                .ok_or(LysisError::ReadUndefinedRegister {
                    reg: *src_reg,
                    at_offset: ctx.offset,
                })?;
            if (*output_idx as usize) < frame.output_slots.len() {
                frame.output_slots[*output_idx as usize] = Some(val);
            }
            Ok(Step::Next)
        }

        _ => unreachable!("non template opcode routed to templates"),
    }
}
