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

use artik::{ElemT, IntBinOp, IntW, Reg};
use num_bigint::BigUint;
use num_traits::Zero;

use crate::ast::BinOp;

use super::big_eval::big_to_le_bytes_trimmed;
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
            // Ordered comparisons demote to `IntW::U64` and dispatch
            // through `IntBinOp::CmpLt` (the only ordered int op
            // Artik exposes), inverting where necessary. U64 covers
            // the bigint witness call graph at `n=64, k=4` where
            // every limb register fits 2^64. Values exceeding `2^64`
            // would truncate unsoundly — the lift's contract is that
            // ordered comparisons run on register-width values, not
            // on accumulators that exceed U64.
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => self.apply_field_compare(op, a, b),
            _ => None,
        }
    }

    fn apply_field_compare(&mut self, op: BinOp, a: Reg, b: Reg) -> Option<Reg> {
        let a_int = self.builder.int_from_field(IntW::U64, a);
        let b_int = self.builder.int_from_field(IntW::U64, b);
        let (lhs_int, rhs_int, invert) = match op {
            BinOp::Lt => (a_int, b_int, false),
            BinOp::Gt => (b_int, a_int, false),
            BinOp::Le => (b_int, a_int, true),
            BinOp::Ge => (a_int, b_int, true),
            _ => unreachable!(),
        };
        // `IntBinOp::CmpLt` is classified boolean by the validator —
        // its destination register is bound to `Int(U8)` regardless of
        // the operand width passed to `IBin`. Promote back through U8
        // to keep register types consistent.
        let cmp_int = self
            .builder
            .ibin(artik::IntBinOp::CmpLt, IntW::U64, lhs_int, rhs_int);
        let cmp_field = self.builder.field_from_int(cmp_int, IntW::U8);
        if invert {
            let one = self.push_const_unsigned(1)?;
            Some(self.builder.fsub(one, cmp_field))
        } else {
            Some(cmp_field)
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
        let v: BigUint = text.parse().ok()?;
        self.push_const_big(&v)
    }

    pub(super) fn push_const_hex(&mut self, text: &str) -> Option<Reg> {
        let v = BigUint::parse_bytes(text.as_bytes(), 16)?;
        self.push_const_big(&v)
    }

    /// Materialize a [`BigUint`] as a field register via the constant
    /// pool. The value is encoded as up to 32 trimmed little-endian
    /// bytes — the canonical representation for the BnLike256 family.
    pub(super) fn push_const_big(&mut self, v: &BigUint) -> Option<Reg> {
        let bytes = big_to_le_bytes_trimmed(v)?;
        let cid = self.builder.intern_const(bytes);
        Some(self.builder.push_const(cid))
    }

    /// Emit `base ^ exp` where `exp` is a compile-time-known
    /// non-negative integer. Implements square-and-multiply on the
    /// LSB-first bits of `exp`. `exp == 0` returns the constant `1`.
    pub(super) fn pow_const_exp(&mut self, base: Reg, exp: &BigUint) -> Option<Reg> {
        if exp.is_zero() {
            return self.push_const_unsigned(1);
        }
        let bits = exp.bits();
        let mut result: Option<Reg> = None;
        let mut squared = base;
        for i in 0..bits {
            if exp.bit(i) {
                result = match result {
                    Some(r) => Some(self.builder.fmul(r, squared)),
                    None => Some(squared),
                };
            }
            if i + 1 < bits {
                squared = self.builder.fmul(squared, squared);
            }
        }
        result
    }

    /// Allocate a 1-element field array used as a mutable slot. The
    /// `while` lift promotes locals reassigned across iterations into
    /// these slots so the executor can read the updated value at each
    /// loop entry.
    pub(super) fn alloc_field_slot(&mut self) -> Reg {
        self.builder.alloc_array(1, ElemT::Field)
    }

    /// Store `value` at index 0 of a slot allocated by
    /// [`Self::alloc_field_slot`].
    pub(super) fn store_field_slot(&mut self, slot: Reg, value: Reg) -> Option<()> {
        let idx = self.push_int_const(0)?;
        self.builder.store_arr(slot, idx, value);
        Some(())
    }

    /// Load the current value held in a field slot.
    pub(super) fn load_field_slot(&mut self, slot: Reg) -> Option<Reg> {
        let idx = self.push_int_const(0)?;
        Some(self.builder.load_arr(slot, idx))
    }

    /// Project a field register onto `{0, 1}` using the
    /// "non-zero is true" convention. The result is a field register
    /// holding `1` if the input was non-zero, `0` otherwise — suitable
    /// for `&&` / `||` muxing or as an early-return predicate.
    pub(super) fn field_to_bool(&mut self, src: Reg) -> Option<Reg> {
        let zero = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(src, zero);
        let is_zero_field = self.builder.field_from_int(is_zero_int, IntW::U8);
        let one = self.push_const_unsigned(1)?;
        Some(self.builder.fsub(one, is_zero_field))
    }

    /// Materialize a compile-time integer as a u32 int register for
    /// use as an array index. Emits two instructions (PushConst into
    /// a field register, then IntFromField U32 into the int register
    /// the executor's LoadArr / StoreArr expect).
    pub(super) fn push_int_const(&mut self, v: u64) -> Option<Reg> {
        let field_reg = self.push_const_unsigned(v as u128)?;
        Some(self.builder.int_from_field(IntW::U32, field_reg))
    }

    /// Compute a flat index for a 2D row-major array as `i * cols + j`.
    /// Both `i` and `j` may be compile-time-known (folded into a
    /// single PushConst) or runtime expressions (lifted to U32 ints
    /// then combined with IBin Add/Mul). Returns the U32-typed index
    /// register the executor's LoadArr / StoreArr expects.
    ///
    /// Bounds check: when both indices fold compile-time, reject if
    /// `i >= rows` or `j >= cols`. Runtime indices defer the check to
    /// the executor's `ArrayIndexOutOfBounds` trap.
    pub(super) fn flatten_2d_index(
        &mut self,
        i: &crate::ast::Expr,
        j: &crate::ast::Expr,
        rows: u32,
        cols: u32,
    ) -> Option<Reg> {
        let i_const = super::helpers::eval_const_expr(i, &self.const_locals);
        let j_const = super::helpers::eval_const_expr(j, &self.const_locals);
        if let (Some(i_v), Some(j_v)) = (i_const, j_const) {
            if !(0..i64::from(rows)).contains(&i_v) || !(0..i64::from(cols)).contains(&j_v) {
                return None;
            }
            let flat = (i_v as u64) * (cols as u64) + (j_v as u64);
            return self.push_int_const(flat);
        }
        // Runtime index: lift each component into a field register,
        // demote to U32, combine via IBin (multiply by `cols`, add).
        let i_field = self.lift_expr(i)?;
        let j_field = self.lift_expr(j)?;
        let i_int = self.demote_to_u32(i_field);
        let j_int = self.demote_to_u32(j_field);
        let cols_field = self.push_const_unsigned(cols as u128)?;
        let cols_int = self.builder.int_from_field(IntW::U32, cols_field);
        let row_offset = self.builder.ibin(IntBinOp::Mul, IntW::U32, i_int, cols_int);
        Some(
            self.builder
                .ibin(IntBinOp::Add, IntW::U32, row_offset, j_int),
        )
    }
}
