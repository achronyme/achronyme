use crate::ir::{Instr, Reg};

use super::{Label, PendingJump, ProgramBuilder};

impl ProgramBuilder {
    // ── Label mechanism ───────────────────────────────────────────────

    /// Create a new unplaced label in the active subprogram. Labels do
    /// not cross subprogram boundaries.
    pub fn new_label(&mut self) -> Label {
        let s = self.cur_mut();
        let id = s.label_positions.len() as u32;
        s.label_positions.push(None);
        Label(id)
    }

    /// Mark the current position in the active subprogram's stream as
    /// the target of `label`. Call exactly once per label.
    pub fn place(&mut self, label: Label) {
        let s = self.cur_mut();
        let pos = s.body.len() as u32;
        s.label_positions[label.0 as usize] = Some(pos);
    }

    /// Emit an unconditional jump to `label`. The target is left as a
    /// sentinel (0) and patched at `finish()` time.
    pub fn jump_to(&mut self, label: Label) {
        let s = self.cur_mut();
        let instr_index = s.body.len() as u32;
        s.body.push(Instr::Jump { target: 0 });
        s.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }

    /// Emit a conditional jump to `label`. `cond` must be an Int-typed
    /// register (typically U8 — any non-zero branches).
    pub fn jump_if_to(&mut self, cond: Reg, label: Label) {
        let s = self.cur_mut();
        let instr_index = s.body.len() as u32;
        s.body.push(Instr::JumpIf { cond, target: 0 });
        s.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }
}
