use super::*;

/// Apply an [`IntBinOp`] to two width-tagged u64 operands. All ops are
/// wrapping in the given width. `Shl`/`Shr` reduce the shift amount
/// modulo the width (matching Rust's `wrapping_shl` semantics for the
/// underlying primitive type).
pub(super) fn apply_bin(op: IntBinOp, w: IntW, a: u64, b: u64) -> u64 {
    let mask = w.mask();
    let a = a & mask;
    let b = b & mask;
    match op {
        IntBinOp::Add => a.wrapping_add(b) & mask,
        IntBinOp::Sub => a.wrapping_sub(b) & mask,
        IntBinOp::Mul => a.wrapping_mul(b) & mask,
        IntBinOp::And => (a & b) & mask,
        IntBinOp::Or => (a | b) & mask,
        IntBinOp::Xor => (a ^ b) & mask,
        IntBinOp::Shl => shl_w(w, a, b),
        IntBinOp::Shr => shr_w(w, a, b),
        IntBinOp::CmpLt => {
            // I64 is signed; others unsigned. Boolean result is 0 or 1.
            let lt = match w {
                IntW::I64 => (a as i64) < (b as i64),
                _ => a < b,
            };
            if lt {
                1
            } else {
                0
            }
        }
        IntBinOp::CmpEq => {
            if a == b {
                1
            } else {
                0
            }
        }
    }
}

fn shl_w(w: IntW, a: u64, b: u64) -> u64 {
    match w {
        IntW::U8 => (a as u8).wrapping_shl(b as u32) as u64,
        IntW::U32 => (a as u32).wrapping_shl(b as u32) as u64,
        IntW::U64 => a.wrapping_shl(b as u32),
        IntW::I64 => (a as i64).wrapping_shl(b as u32) as u64,
    }
}

fn shr_w(w: IntW, a: u64, b: u64) -> u64 {
    match w {
        IntW::U8 => (a as u8).wrapping_shr(b as u32) as u64,
        IntW::U32 => (a as u32).wrapping_shr(b as u32) as u64,
        IntW::U64 => a.wrapping_shr(b as u32),
        IntW::I64 => ((a as i64).wrapping_shr(b as u32)) as u64,
    }
}
