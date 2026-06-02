use super::helpers::jump_targets;
use akron::opcode::instruction::*;
use akron::opcode::OpCode;

// ── Pass 1: Redundant Load Elimination ──────────────────────────────────

/// Replace `SetGlobal Ra, idx; GetGlobal Rb, idx` → `SetGlobal Ra, idx; Move Rb, Ra`
/// when there is no jump target on the GetGlobal (i.e. it cannot be reached
/// from another path that might have a different value for the global).
pub(super) fn redundant_load_elim(instrs: &mut [(u32, u32)]) {
    if instrs.len() < 2 {
        return;
    }
    let targets = jump_targets(instrs);

    for i in 0..instrs.len() - 1 {
        let (w0, _) = instrs[i];
        let (w1, _) = instrs[i + 1];

        let op0 = decode_opcode(w0);
        let op1 = decode_opcode(w1);

        if op0 != OpCode::SetGlobal.as_u8() || op1 != OpCode::GetGlobal.as_u8() {
            continue;
        }

        // Same global index?
        let idx0 = decode_bx(w0);
        let idx1 = decode_bx(w1);
        if idx0 != idx1 {
            continue;
        }

        // Jump target barrier?
        if targets[i + 1] {
            continue;
        }

        // Replace GetGlobal Rb, idx → Move Rb, Ra
        let ra = decode_a(w0); // register that was written to the global
        let rb = decode_a(w1); // register that wants the global's value
        instrs[i + 1].0 = encode_abc(OpCode::Move.as_u8(), rb, ra, 0);
    }
}
