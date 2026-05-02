//! Artik builder primitives — register-level emitters.
//!
//! Methods that wrap the [`artik::ProgramBuilder`] API into the lift's
//! preferred shapes:
//!
//! - [`LiftState::apply_field_binop`] — dispatch a [`BinOp`] over field
//!   registers; bit ops promote to [`IntW::U32`] via
//!   [`LiftState::demote_to_u32`], apply at integer width, then promote
//!   back via [`LiftState::promote_u32_to_field`].
//! - [`LiftState::push_const_int`] / `push_const_unsigned` /
//!   `push_const_dec` / `push_const_hex` — constant-pool emitters with
//!   sign-correct encoding.
//! - [`LiftState::push_int_const`] — materialize a compile-time integer
//!   as a [`IntW::U32`] register for `LoadArr` / `StoreArr`.

use artik::{IntBinOp, IntW, Reg};

use crate::ast::BinOp;

use super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Apply a binary op to two field-typed registers. Field ops
    /// (`+`, `-`, `*`, `/`) stay in the field; bit ops promote both
    /// operands to `IntW::U32`, apply the integer op, and promote
    /// back. The u32 width is a deliberate MVP choice — it covers
    /// SHA-256, BLAKE2s, and every other 32-bit witness gadget we
    /// care about today. Wider (u64) bit ops would need per-call
    /// width inference.
    pub(super) fn apply_field_binop(&mut self, op: BinOp, a: Reg, b: Reg) -> Option<Reg> {
        match op {
            BinOp::Add => Some(self.builder.fadd(a, b)),
            BinOp::Sub => Some(self.builder.fsub(a, b)),
            BinOp::Mul => Some(self.builder.fmul(a, b)),
            BinOp::Div => Some(self.builder.fdiv(a, b)),
            BinOp::BitAnd => Some(self.apply_int_binop_u32(IntBinOp::And, a, b)),
            BinOp::BitOr => Some(self.apply_int_binop_u32(IntBinOp::Or, a, b)),
            BinOp::BitXor => Some(self.apply_int_binop_u32(IntBinOp::Xor, a, b)),
            BinOp::ShiftL => Some(self.apply_int_binop_u32(IntBinOp::Shl, a, b)),
            BinOp::ShiftR => Some(self.apply_int_binop_u32(IntBinOp::Shr, a, b)),
            _ => None,
        }
    }

    /// Demote a field reg to `IntW::U32` via `IntFromField`.
    pub(super) fn demote_to_u32(&mut self, field_reg: Reg) -> Reg {
        self.builder.int_from_field(IntW::U32, field_reg)
    }

    /// Promote a `IntW::U32` reg back to field via `FieldFromInt`.
    pub(super) fn promote_u32_to_field(&mut self, int_reg: Reg) -> Reg {
        self.builder.field_from_int(int_reg, IntW::U32)
    }

    /// Common scaffolding for bit ops: demote `a` and `b` to u32,
    /// apply the integer op at u32 width, and promote the result
    /// back to a field register.
    fn apply_int_binop_u32(&mut self, op: IntBinOp, a: Reg, b: Reg) -> Reg {
        let a_int = self.demote_to_u32(a);
        let b_int = self.demote_to_u32(b);
        let dst_int = self.builder.ibin(op, IntW::U32, a_int, b_int);
        self.promote_u32_to_field(dst_int)
    }

    pub(super) fn push_const_int(&mut self, v: ConstInt) -> Option<Reg> {
        // Negative values need sign-correct encoding. `FieldFromInt I64`
        // is what we'd use at the executor level, but we don't have
        // int registers on this path — constants enter the register
        // file via `PushConst` (field). Encode a negative value as
        // `p - |v|` at lift time by passing through `from_i64` on the
        // wire side: we serialize the *unsigned* representation of the
        // constant (`(-v) as u64`) and flip sign with `0 - x` via an
        // FSub against a zero const. For positive values, the normal
        // LE encoding is correct.
        if v < 0 {
            let positive = self.push_const_unsigned(v.unsigned_abs() as u128)?;
            let zero = self.push_const_unsigned(0)?;
            return Some(self.builder.fsub(zero, positive));
        }
        self.push_const_unsigned(v as u128)
    }

    pub(super) fn push_const_unsigned(&mut self, v: u128) -> Option<Reg> {
        let mut bytes: Vec<u8> = v.to_le_bytes().to_vec();
        while bytes.last() == Some(&0) && bytes.len() > 1 {
            bytes.pop();
        }
        let cid = self.builder.intern_const(bytes);
        Some(self.builder.push_const(cid))
    }

    pub(super) fn push_const_dec(&mut self, text: &str) -> Option<Reg> {
        let v: u128 = text.parse().ok()?;
        self.push_const_unsigned(v)
    }

    pub(super) fn push_const_hex(&mut self, text: &str) -> Option<Reg> {
        let v = u128::from_str_radix(text, 16).ok()?;
        self.push_const_unsigned(v)
    }

    /// Materialize a compile-time integer as a u32 int register for
    /// use as an array index. Emits two instructions (PushConst into
    /// a field register, then IntFromField U32 into the int register
    /// the executor's LoadArr / StoreArr expect).
    pub(super) fn push_int_const(&mut self, v: u64) -> Option<Reg> {
        let field_reg = self.push_const_unsigned(v as u128)?;
        Some(self.builder.int_from_field(IntW::U32, field_reg))
    }
}
