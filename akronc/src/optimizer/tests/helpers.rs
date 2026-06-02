pub(super) use super::super::constant_hoist::constant_hoisting;
pub(super) use super::super::helpers::{dest_reg, find_loops, jump_targets};
pub(super) use super::super::optimize;
pub(super) use super::super::redundant_load::redundant_load_elim;
pub(super) use super::super::register_promotion::register_promotion;
pub(super) use akron::opcode::instruction::*;
pub(super) use akron::opcode::OpCode;

/// Helper: build an ABx instruction
pub(super) fn abx(op: OpCode, a: u8, bx: u16) -> u32 {
    encode_abx(op.as_u8(), a, bx)
}

/// Helper: build an ABC instruction
pub(super) fn abc(op: OpCode, a: u8, b: u8, c: u8) -> u32 {
    encode_abc(op.as_u8(), a, b, c)
}
