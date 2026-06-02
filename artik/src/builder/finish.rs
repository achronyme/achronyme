use crate::ir::Instr;
use crate::program::{Program, Subprogram};

use super::{BuilderError, ProgramBuilder, SubInProgress};

impl ProgramBuilder {
    // ── Finalize ────────────────────────────────────────────────────

    /// Consume the builder and produce a [`Program`], patching every
    /// subprogram's pending jump targets into the byte offsets they
    /// land at. A builder that never reserved a subprogram yields a
    /// single entry subprogram — the same shape `Program::new`
    /// produces. Returns an error if any label was referenced but
    /// never placed.
    pub fn finish(mut self) -> Result<Program, BuilderError> {
        let mut subprograms = Vec::with_capacity(self.subs.len());
        for sub in std::mem::take(&mut self.subs) {
            subprograms.push(Self::resolve_sub(sub)?);
        }
        Ok(Program::from_subprograms(
            self.family,
            std::mem::take(&mut self.const_pool),
            subprograms,
        ))
    }

    /// Resolve one subprogram's pending jumps (instruction index →
    /// byte offset within that subprogram's standalone stream) and
    /// finalize it into a [`Subprogram`].
    fn resolve_sub(mut sub: SubInProgress) -> Result<Subprogram, BuilderError> {
        // Pass 1: byte offset of each instruction index. `encoded_size`
        // depends on the instruction (including its operand list, for
        // the variable-length Call / Return), so walk the final body.
        let mut index_to_offset: Vec<u32> = Vec::with_capacity(sub.body.len() + 1);
        let mut acc: u32 = 0;
        for ins in &sub.body {
            index_to_offset.push(acc);
            acc = acc.saturating_add(ins.encoded_size());
        }
        // Sentinel — offset past the last instruction, in case a label
        // is placed at the very end ("fall through to the end").
        index_to_offset.push(acc);

        // Pass 2: patch pending jumps with the resolved byte offsets.
        for pending in &sub.pending_jumps {
            let target_index = sub
                .label_positions
                .get(pending.label as usize)
                .and_then(|p| *p)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            let target_offset = *index_to_offset
                .get(target_index as usize)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            match sub.body.get_mut(pending.instr_index as usize) {
                Some(Instr::Jump { target }) | Some(Instr::JumpIf { target, .. }) => {
                    *target = target_offset;
                }
                _ => {
                    // The builder only records pending patches for Jump
                    // / JumpIf sites, so any other opcode here means the
                    // body was mutated behind the builder's back.
                    return Err(BuilderError::NonJumpAtPatchSite(pending.instr_index));
                }
            }
        }

        Ok(Subprogram {
            frame_size: sub.next_reg,
            params: std::mem::take(&mut sub.params),
            returns: std::mem::take(&mut sub.returns),
            body: std::mem::take(&mut sub.body),
        })
    }
}
