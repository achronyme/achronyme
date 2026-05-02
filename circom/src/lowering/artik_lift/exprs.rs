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

use artik::{IntW, Reg};

use crate::ast::{Expr, UnaryOp};

use super::helpers::{eval_const_expr, extract_call_name};
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
            Expr::BinOp { op, lhs, rhs, .. } => {
                let a = self.lift_expr(lhs)?;
                let c = self.lift_expr(rhs)?;
                self.apply_field_binop(*op, a, c)
            }
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
                // `arr[i]` where `arr` is a declared array. Two
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
                let (arr_reg, len) = self.arrays.get(name).copied()?;
                let idx_reg = if let Some(idx) = eval_const_expr(index, &self.const_locals) {
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    self.push_int_const(idx as u64)?
                } else {
                    let idx_field = self.lift_expr(index)?;
                    self.builder.int_from_field(IntW::U32, idx_field)
                };
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
                    NestedResult::Array(_, _) => None,
                }
            }
            _ => None,
        }
    }

    /// Inline a nested function call into the current Artik program.
    /// Swaps the current scope (locals / arrays / const_locals) for
    /// a fresh one bound to the callee's params, walks the callee's
    /// body, captures the return value via `nested_result`, and
    /// restores the outer scope.
    fn lift_nested_call(&mut self, name: &str, args: &[Expr]) -> Option<NestedResult> {
        let func = self.functions.get(name).copied()?;
        if args.len() != func.params.len() {
            return None;
        }

        // Simple recursion guard — the outer inline-depth counter
        // lives in `LoweringContext` but we don't carry that here.
        // A fixed ceiling on nested lift depth prevents programs
        // that accidentally recurse through mutually-calling
        // functions from exhausting the stack.
        if self.nested_depth >= 32 {
            return None;
        }

        // Evaluate args in the outer scope first.
        let mut arg_regs = Vec::with_capacity(args.len());
        for arg in args {
            arg_regs.push(self.lift_expr(arg)?);
        }

        // Swap scope.
        let outer_locals = std::mem::take(&mut self.locals);
        let outer_const = std::mem::take(&mut self.const_locals);
        let outer_arrays = std::mem::take(&mut self.arrays);
        let outer_halted = self.halted;
        let outer_result = self.nested_result.take();
        self.halted = false;
        self.nested_depth += 1;

        for (param, reg) in func.params.iter().zip(arg_regs.iter()) {
            self.locals.insert(param.clone(), *reg);
        }

        // Lift the callee's body.
        let mut body_ok = true;
        for stmt in &func.body.stmts {
            if self.lift_stmt(stmt).is_none() {
                body_ok = false;
                break;
            }
            if self.halted {
                break;
            }
        }

        let result = self.nested_result.take();

        // Restore outer scope regardless of outcome so the program
        // state stays sane even when a nested lift bails out.
        self.nested_result = outer_result;
        self.nested_depth -= 1;
        self.halted = outer_halted;
        self.locals = outer_locals;
        self.const_locals = outer_const;
        self.arrays = outer_arrays;

        if !body_ok {
            return None;
        }
        result
    }

    pub(super) fn lookup_ident(&mut self, name: &str) -> Option<Reg> {
        if let Some(v) = self.const_locals.get(name).copied() {
            return self.push_const_int(v);
        }
        self.locals.get(name).copied()
    }
}
