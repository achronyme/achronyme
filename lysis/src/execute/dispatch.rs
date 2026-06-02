use memory::field::{FieldBackend, FieldElement};

use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::intern::NodeId;
use crate::program::Program;

use super::frame::Frame;
use super::ir_sink::IrSink;
use super::step::Step;

mod emit;
mod env_control;
mod heap;
mod templates;

pub(super) struct DispatchCtx<'a, F: FieldBackend, S: IrSink<F>> {
    pub(super) offset: u32,
    pub(super) frame_idx: usize,
    pub(super) frames: &'a mut [Frame],
    pub(super) program: &'a Program<F>,
    pub(super) captures: &'a [FieldElement<F>],
    pub(super) config: &'a LysisConfig,
    pub(super) sink: &'a mut S,
    pub(super) template_lookup: &'a [Option<crate::program::Template>],
    pub(super) template_body_ranges: &'a [Option<(usize, usize)>],
    pub(super) heap: &'a mut [Option<NodeId>],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch<F: FieldBackend, S: IrSink<F>>(
    instr: &crate::program::Instr,
    frame_idx: usize,
    frames: &mut [Frame],
    program: &Program<F>,
    captures: &[FieldElement<F>],
    config: &LysisConfig,
    sink: &mut S,
    template_lookup: &[Option<crate::program::Template>],
    template_body_ranges: &[Option<(usize, usize)>],
    heap: &mut [Option<NodeId>],
) -> Result<Step, LysisError> {
    use Opcode::*;

    let mut ctx = DispatchCtx {
        offset: instr.offset,
        frame_idx,
        frames,
        program,
        captures,
        config,
        sink,
        template_lookup,
        template_body_ranges,
        heap,
    };

    match &instr.opcode {
        LoadCapture { .. }
        | LoadConst { .. }
        | LoadInput { .. }
        | EnterScope
        | ExitScope
        | Jump { .. }
        | JumpIf { .. }
        | Return
        | Halt
        | Trap { .. }
        | LoopUnroll { .. }
        | LoopRolled { .. }
        | LoopRange { .. } => env_control::dispatch(&instr.opcode, &mut ctx),

        DefineTemplate { .. } | InstantiateTemplate { .. } | TemplateOutput { .. } => {
            templates::dispatch(&instr.opcode, &mut ctx)
        }

        EmitConst { .. }
        | EmitAdd { .. }
        | EmitSub { .. }
        | EmitMul { .. }
        | EmitDiv { .. }
        | EmitNeg { .. }
        | EmitMux { .. }
        | EmitDecompose { .. }
        | EmitAssertEq { .. }
        | EmitAssertEqMsg { .. }
        | EmitRangeCheck { .. }
        | EmitWitnessCall { .. }
        | EmitPoseidonHash { .. }
        | EmitIsEq { .. }
        | EmitIsLt { .. }
        | EmitIntDiv { .. }
        | EmitIntMod { .. } => emit::dispatch(&instr.opcode, &mut ctx),

        StoreHeap { .. } | LoadHeap { .. } | EmitWitnessCallHeap { .. } => {
            heap::dispatch(&instr.opcode, &mut ctx)
        }
    }
}
