//! Call-stack frame layout.
//!
//! A Lysis execution has a `Vec<Frame>` call stack. Each frame owns
//! its register file and a program counter. `InstantiateTemplate`
//! pushes a new frame; `Return` pops it. The top-level body runs in
//! the initial frame and only terminates via `Halt` (or `Trap`).

use crate::intern::NodeId;

/// Runtime state for one active `LoopUnroll` instance. Frames may
/// stack these for nested loops.
#[derive(Debug, Clone, Copy)]
pub struct LoopState {
    /// Register holding the iteration-counter `Const` node id.
    pub iter_reg: u8,
    /// Loop lower bound (inclusive).
    pub start: u32,
    /// Loop upper bound (exclusive).
    pub end: u32,
    /// Value of the iteration counter for the currently-running
    /// iteration. `start` on entry; increments on each iteration.
    pub current: u32,
    /// First instruction index inside the body.
    pub body_start_idx: usize,
    /// One-past-last instruction index inside the body (same
    /// semantics as `Frame::body_end_idx`).
    pub body_end_idx: usize,
}

/// One activation of a template body (or the top-level body).
#[derive(Debug, Clone)]
pub struct Frame {
    /// Register file. `regs[i] = None` means "not yet written to".
    pub regs: Vec<Option<NodeId>>,
    /// Current instruction index into `Program::body`.
    pub pc: usize,
    /// First instruction index the frame may execute.
    pub body_start_idx: usize,
    /// One-past-last instruction index the frame may execute.
    pub body_end_idx: usize,
    /// `None` for the top-level frame, `Some(id)` for a template call.
    pub template_id: Option<u16>,
    /// Outputs collected from `TemplateOutput` opcodes, indexed by
    /// `output_idx`. Drained into the caller's `output_regs` on `Return`.
    pub output_slots: Vec<Option<NodeId>>,
    /// Caller-side register numbers to populate on `Return`. Empty
    /// for the top-level frame.
    pub caller_output_regs: Vec<u8>,
    /// Caller frame's index in the stack, used by the pop path to
    /// write outputs back. `None` for the top-level frame.
    pub caller_frame_idx: Option<usize>,
    /// Active `LoopUnroll` instances in this frame. Innermost loop
    /// is at the back; empty when no loop is running.
    pub loop_stack: Vec<LoopState>,
}

impl Frame {
    /// Top-level frame with a 256-register file (matches the Phase 1
    /// implicit-root frame size documented in `bytecode::validate`).
    pub fn root(body_end_idx: usize) -> Self {
        Self {
            regs: vec![None; 256],
            pc: 0,
            body_start_idx: 0,
            body_end_idx,
            template_id: None,
            output_slots: Vec::new(),
            caller_output_regs: Vec::new(),
            caller_frame_idx: None,
            loop_stack: Vec::new(),
        }
    }

    /// Activation of a template body with its declared frame size.
    pub fn for_template(
        template_id: u16,
        frame_size: u8,
        body_start_idx: usize,
        body_end_idx: usize,
        output_count: usize,
        caller_output_regs: Vec<u8>,
        caller_frame_idx: usize,
    ) -> Self {
        Self {
            regs: vec![None; frame_size as usize],
            pc: body_start_idx,
            body_start_idx,
            body_end_idx,
            template_id: Some(template_id),
            output_slots: vec![None; output_count],
            caller_output_regs,
            caller_frame_idx: Some(caller_frame_idx),
            loop_stack: Vec::new(),
        }
    }

    /// Read a register, returning `None` on uninitialized access.
    #[inline]
    pub fn read(&self, reg: u8) -> Option<NodeId> {
        self.regs.get(reg as usize).copied().flatten()
    }

    /// Write a register.
    #[inline]
    pub fn write(&mut self, reg: u8, id: NodeId) {
        if (reg as usize) < self.regs.len() {
            self.regs[reg as usize] = Some(id);
        }
    }
}
