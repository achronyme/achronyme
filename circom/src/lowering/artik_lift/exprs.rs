//! Expression lift.
//!
//! [`LiftState::lift_expr`] is the dispatcher: literals, identifiers,
//! field arithmetic, bit ops (via `IntW::U32` round-trip), array
//! indexing, and nested function calls.
//!
//! [`LiftState::lift_nested_call`] inlines the callee's body into the
//! current Artik program — swap scope, walk body, capture the return via
//! `nested_result`, restore scope.
//!
//! [`LiftState::lookup_ident`] resolves an identifier through
//! `const_locals` (compile-time), `arrays`, and `locals` (runtime
//! register) in order.

use std::collections::HashMap;

use artik::{IntW, Reg};

use crate::ast::{BinOp, Expr, UnaryOp};

use super::big_eval::try_eval_big;
use super::bytecode::PeelLhs;
use super::helpers::{eval_const_expr, expr_is_one, extract_call_name};
use super::{LiftState, NestedResult};

impl<'f> LiftState<'f> {
    pub(super) fn lift_expr(&mut self, expr: &Expr) -> Option<Reg> {
        match expr {
            Expr::Ident { name, .. } => self.lookup_ident(name),
            Expr::Number { value, .. } => self.push_const_dec(value),
            Expr::HexNumber { value, .. } => {
                let trimmed = value.strip_prefix("0x").unwrap_or(value);
                self.push_const_hex(trimmed)
            }
            Expr::BinOp { op, lhs, rhs, .. } => match op {
                // `**` requires a compile-time-known non-negative
                // exponent — circomlib's modular sqrt uses this for
                // Legendre tests and Tonelli-Shanks setup.
                BinOp::Pow => {
                    let exp = try_eval_big(rhs, &HashMap::new(), &self.const_locals)?;
                    let base = self.lift_expr(lhs)?;
                    self.pow_const_exp(base, &exp)
                }
                // `&&` / `||` on field values: evaluate to `{0, 1}`
                // via the standard "non-zero is true" projection. Both
                // operands are lifted unconditionally, matching the
                // mux-style if/else lowering. Each non-zero check is
                // `1 - feq(x, 0)`.
                BinOp::And | BinOp::Or => {
                    let a = self.lift_expr(lhs)?;
                    let b = self.lift_expr(rhs)?;
                    let a_bool = self.field_to_bool(a)?;
                    let b_bool = self.field_to_bool(b)?;
                    match op {
                        BinOp::And => Some(self.builder.fmul(a_bool, b_bool)),
                        BinOp::Or => {
                            let prod = self.builder.fmul(a_bool, b_bool);
                            let sum = self.builder.fadd(a_bool, b_bool);
                            Some(self.builder.fsub(sum, prod))
                        }
                        _ => unreachable!(),
                    }
                }
                // `==` / `!=`: emit FEq (returns IntW::U8 0/1) then
                // promote to a field {0, 1}.
                BinOp::Eq | BinOp::Neq => {
                    let a = self.lift_expr(lhs)?;
                    let b = self.lift_expr(rhs)?;
                    let eq_int = self.builder.feq(a, b);
                    let eq_field = self.builder.field_from_int(eq_int, IntW::U8);
                    match op {
                        BinOp::Eq => Some(eq_field),
                        BinOp::Neq => {
                            let one = self.push_const_unsigned(1)?;
                            Some(self.builder.fsub(one, eq_field))
                        }
                        _ => unreachable!(),
                    }
                }
                // `\` (IntDiv) and `%` (Mod) on field values: dispatch
                // to `lift_int_div_mod` which recognizes
                // `1 << <const k>` shapes (FShr / FAnd) and falls back
                // to runtime FIDiv / FIRem otherwise.
                BinOp::IntDiv | BinOp::Mod => self.lift_int_div_mod(*op, lhs, rhs),
                // `1 << n` is circom's field-precision power-of-two
                // (used as a base-2^n limb radix / modulus / scale),
                // not a fixed-width bit-packing shift — those always
                // shift a signal or limb base, never the literal `1`.
                // Lower it to `FPow2` so the result is `2^n` in the
                // field; a width-masked integer shift would return `1`
                // for any `n` that is a multiple of the int width.
                BinOp::ShiftL if expr_is_one(lhs) => {
                    let amount = self.lift_expr(rhs)?;
                    Some(self.builder.fpow2(amount))
                }
                _ => self.lift_field_binop(*op, PeelLhs::Expr(lhs.as_ref()), rhs),
            },
            Expr::UnaryOp {
                op: UnaryOp::Neg,
                operand,
                ..
            } => {
                // `-x` becomes `0 - x`. Keeping this in-scope matches
                // the trivial-inline path's behavior.
                let zero = self.push_const_int(0)?;
                let r = self.lift_expr(operand)?;
                Some(self.builder.fsub(zero, r))
            }
            Expr::UnaryOp {
                op: UnaryOp::BitNot,
                operand,
                ..
            } => {
                // `~x` — promote to u32, INot, promote back.
                let r = self.lift_expr(operand)?;
                let r_int = self.demote_to_u32(r);
                let not_int = self.builder.inot(IntW::U32, r_int);
                Some(self.promote_u32_to_field(not_int))
            }
            Expr::Index { object, index, .. } => {
                // 2D index read: `arr[i][j]` is a nested Index AST.
                if let Expr::Index {
                    object: inner_obj,
                    index: inner_idx,
                    ..
                } = object.as_ref()
                {
                    let Expr::Ident { name, .. } = inner_obj.as_ref() else {
                        return None;
                    };
                    let shape = self.arrays.get(name).copied()?;
                    let (handle, rows, cols) = match shape {
                        super::ArrayShape::Flat2D { handle, rows, cols } => (handle, rows, cols),
                        super::ArrayShape::Flat1D { .. } => return None,
                    };
                    let flat_idx_reg = self.flatten_2d_index(inner_idx, index, rows, cols)?;
                    return Some(self.builder.load_arr(handle, flat_idx_reg));
                }

                // 1D `arr[i]` where `arr` is a declared array. Two
                // index shapes are honored:
                //   - compile-time index → range-check against the
                //     declared length and materialize the index
                //     register via PushConst → IntFromField.
                //   - runtime index (e.g. a scalar parameter or a
                //     register-valued local) → lift the index
                //     expression into a field register, then
                //     IntFromField U32 into the int register the
                //     executor's LoadArr expects. Required by
                //     circomlib's `sha256K(i)` (single indexed read
                //     with a runtime `i`). The executor traps on
                //     out-of-bounds access, so the bounds check is
                //     deferred rather than duplicated here.
                let Expr::Ident { name, .. } = object.as_ref() else {
                    return None;
                };
                let (arr_reg, len) = self.arrays.get(name).copied()?.as_1d()?;
                if let Some(idx) = eval_const_expr(index, &self.const_locals) {
                    // Compile-time index. Negative is unconditionally a
                    // bug — the lift bails. An index past the declared
                    // length matches circom's witness-calculator
                    // semantic of returning 0 for unwritten slots: the
                    // bigint helpers in circomlib (`long_sub`,
                    // `long_gt`) read `b[k]` past the caller's array
                    // length under the assumption that out-of-bounds
                    // yields zero. Emit a constant zero to preserve
                    // those callers without paying for an alloc-time
                    // pad.
                    if idx < 0 {
                        return None;
                    }
                    if idx >= i64::from(len) {
                        return self.push_const_unsigned(0);
                    }
                    let idx_reg = self.push_int_const(idx as u64)?;
                    return Some(self.builder.load_arr(arr_reg, idx_reg));
                }
                let idx_field = self.lift_expr(index)?;
                let idx_reg = self.builder.int_from_field(IntW::U32, idx_field);
                Some(self.builder.load_arr(arr_reg, idx_reg))
            }
            Expr::Call { callee, args, .. } => {
                // Nested function call. Lift the callee's body into
                // the same Artik program as this function, with the
                // callee's params bound to arg-evaluated registers.
                // Array returns are not representable as a single
                // `Reg`; those currently bail out so the outer lift
                // falls back to E212.
                let name = extract_call_name(callee)?;
                match self.lift_nested_call(&name, args)? {
                    NestedResult::Scalar(r) => Some(r),
                    NestedResult::Array(_, _) | NestedResult::Array2D(_, _, _) => None,
                }
            }
            _ => None,
        }
    }

    /// Lift a callee that returns a 1D Field array — used by
    /// `var arr[N] = call(...)` and `arr2d[i] = call(...)` patterns.
    /// Returns `None` if the call doesn't lift, doesn't return an
    /// array, or the call site is not a bare `Expr::Call`.
    pub(super) fn lift_call_returning_array(
        &mut self,
        callee: &Expr,
        args: &[Expr],
    ) -> Option<(Reg, u32)> {
        let name = extract_call_name(callee)?;
        match self.lift_nested_call(&name, args)? {
            NestedResult::Array(h, len) => Some((h, len)),
            NestedResult::Scalar(_) | NestedResult::Array2D(_, _, _) => None,
        }
    }

    /// Lift a callee that returns a 2D Field array. Used by
    /// `var arr[R][C] = call(...)` (alias) and `arr2d = call(...)`
    /// (whole-shape rebind) patterns where the callee's body ends in
    /// `return <local 2D array>`.
    pub(super) fn lift_call_returning_array_2d(
        &mut self,
        callee: &Expr,
        args: &[Expr],
    ) -> Option<(Reg, u32, u32)> {
        let name = extract_call_name(callee)?;
        match self.lift_nested_call(&name, args)? {
            NestedResult::Array2D(h, rows, cols) => Some((h, rows, cols)),
            NestedResult::Scalar(_) | NestedResult::Array(_, _) => None,
        }
    }

    /// Lift a nested function call as a real Artik subprogram
    /// `Call` to a callee subprogram, mapping its result registers
    /// back to a [`NestedResult`] for the call-result consumers.
    pub(super) fn lift_nested_call(&mut self, name: &str, args: &[Expr]) -> Option<NestedResult> {
        self.lift_nested_call_subprogram(name, args)
    }

    pub(super) fn lookup_ident(&mut self, name: &str) -> Option<Reg> {
        if let Some(v) = self.const_locals.get(name).copied() {
            return self.push_const_int(v);
        }
        self.locals.get(name).copied()
    }
}
