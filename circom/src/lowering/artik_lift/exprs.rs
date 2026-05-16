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

use artik::{ElemT, IntW, Reg};

use crate::ast::{BinOp, Expr, UnaryOp};

use super::big_eval::try_eval_big;
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
                _ => {
                    let a = self.lift_expr(lhs)?;
                    let c = self.lift_expr(rhs)?;
                    self.apply_field_binop(*op, a, c)
                }
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

    /// Inline a nested function call into the current Artik program.
    /// Swaps the current scope (locals / arrays / const_locals) for
    /// a fresh one bound to the callee's params, walks the callee's
    /// body, captures the return value via `nested_result`, and
    /// restores the outer scope.
    ///
    /// Array arguments alias the caller's array handle directly into
    /// the callee's `arrays` map under the callee's param name —
    /// arrays live on the Artik heap and are passed by reference
    /// across the inline boundary. Scalar arguments lift into a
    /// register; compile-time-folded scalars also seed the callee's
    /// `const_locals` so pow-of-2 patterns like `1 << n` recognize
    /// the divisor at lift time.
    pub(super) fn lift_nested_call(&mut self, name: &str, args: &[Expr]) -> Option<NestedResult> {
        // On the subprogram path a nested call becomes a real Artik
        // `Call`; the inlining body below runs only when no driver is
        // present, so it stays byte-identical.
        if self.driver.is_some() {
            return self.lift_nested_call_subprogram(name, args);
        }
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

        // Snapshot the builder so a partial nested lift — orphan arg
        // emission + any bytecode emitted into the body before bail —
        // rolls back cleanly. Without this, a fallback (promote the
        // call as a standalone WitnessCall instead of inlining) cannot
        // start from a clean parent state.
        let pre_call_snapshot = self.builder.snapshot();

        // Classify each argument as scalar (lift to register) or array
        // (alias caller's handle). Capture compile-time-folded scalars
        // so the callee's frame can bind them into `const_locals` —
        // this is what lets patterns like `1 << n` fold at lift time
        // when the caller passes a literal for `n`.
        enum NestedArg {
            Scalar {
                reg: Reg,
                const_val: Option<super::ConstInt>,
            },
            Array(super::ArrayShape),
        }
        let mut nested_args: Vec<NestedArg> = Vec::with_capacity(args.len());
        for arg in args {
            if let Expr::Ident { name: arg_name, .. } = arg {
                if let Some(&shape) = self.arrays.get(arg_name) {
                    nested_args.push(NestedArg::Array(shape));
                    continue;
                }
            }
            // Row-slice arg: `f(..., arr2d[row], ...)` where the source
            // is a Flat2D local and `row` const-folds. Materialize the
            // row as a fresh Flat1D so the callee binds it as an array
            // parameter, mirroring how a bare ident with `Flat1D` shape
            // is forwarded above. circomlib's bigint composers pass row
            // slices (e.g. `b[1]` from `var b[2][100]`) into 1D-array
            // helpers like `long_sub_mod_p`.
            if let Expr::Index { object, index, .. } = arg {
                if let Expr::Ident { name: arg_name, .. } = object.as_ref() {
                    if let Some(super::ArrayShape::Flat2D {
                        handle: src_handle,
                        rows,
                        cols,
                    }) = self.arrays.get(arg_name).copied()
                    {
                        if let Some(row_shape) =
                            self.materialize_row_slice(src_handle, rows, cols, index)
                        {
                            nested_args.push(NestedArg::Array(row_shape));
                            continue;
                        }
                    }
                }
            }
            let reg = self.lift_expr(arg)?;
            let const_val = super::helpers::eval_const_expr(arg, &self.const_locals);
            nested_args.push(NestedArg::Scalar { reg, const_val });
        }

        // Swap scope.
        let outer_locals = std::mem::take(&mut self.locals);
        let outer_const = std::mem::take(&mut self.const_locals);
        let outer_arrays = std::mem::take(&mut self.arrays);
        let outer_halted = self.halted;
        let outer_result = self.nested_result.take();
        let outer_return_slot = self.nested_return_slot.take();
        let outer_end_label = self.nested_end_label.take();
        let outer_array_return_slot = self.nested_array_return_slot.take();
        // Reserve a 1-element heap slot and a jump target so each
        // scalar `return` inside the callee body can write its value
        // and exit cleanly. Without this, a return nested inside a
        // conditional or unrolled loop would emit only a `PushConst`
        // and the lift would record the register of whichever return
        // it walked past last — the runtime would then run every
        // emission and the caller would observe the trailing
        // fall-through value, not the one the guard selected.
        let scalar_return_slot = self.alloc_field_slot();
        let scalar_end_label = self.builder.new_label();
        self.nested_return_slot = Some(scalar_return_slot);
        self.nested_end_label = Some(scalar_end_label);
        // Symmetric setup for array-shaped returns. A pre-scan of
        // the body identifies whether every `return` resolves to the
        // same array length — `Expr::ArrayLit` lengths are syntactic,
        // `Expr::Ident` lengths come from `var X[K]` declarations
        // whose dim folds against the callee's incoming param
        // consts. When the scan agrees on a length, allocate the
        // destination heap array at frame entry so the AllocArray
        // bytecode unconditionally precedes any return-site store.
        // Without the pre-allocation, a lazy alloc inside the first-
        // return branch would leak an uninitialised handle to any
        // other return whose branch runs at runtime in its place.
        let mut scan_consts: std::collections::HashMap<String, super::ConstInt> =
            std::collections::HashMap::new();
        for (param, na) in func.params.iter().zip(nested_args.iter()) {
            if let NestedArg::Scalar {
                const_val: Some(v), ..
            } = na
            {
                scan_consts.insert(param.clone(), *v);
            }
        }
        if let super::helpers::ArrayReturnScan::Fixed(len) =
            super::helpers::scan_array_returns(&func.body.stmts, &scan_consts)
        {
            let handle = self.builder.alloc_array(len, ElemT::Field);
            self.nested_array_return_slot = Some((handle, len));
        }
        self.halted = false;
        self.nested_depth += 1;

        for (param, na) in func.params.iter().zip(nested_args.iter()) {
            match na {
                NestedArg::Scalar { reg, const_val } => {
                    self.locals.insert(param.clone(), *reg);
                    if let Some(v) = const_val {
                        self.const_locals.insert(param.clone(), *v);
                    }
                }
                NestedArg::Array(shape) => {
                    self.arrays.insert(param.clone(), *shape);
                }
            }
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

        let mut result = self.nested_result.take();
        let array_slot_after = self.nested_array_return_slot;

        // Resolve the call's outward-facing result. Each return shape
        // routes through exactly one channel:
        //
        // * `nested_result` carries a 2D-array return (the only
        //   shape that bypasses the slot machinery today).
        // * `nested_array_return_slot` carries a 1D array return: the
        //   destination handle is the slot itself, and the length was
        //   fixed by the pre-scan.
        // * `nested_return_slot` carries a scalar return: place the
        //   end-label and load the slot.
        if body_ok && result.is_none() && self.halted {
            self.builder.place(scalar_end_label);
            if let Some((handle, len)) = array_slot_after {
                result = Some(NestedResult::Array(handle, len));
            } else if let Some(loaded) = self.load_field_slot(scalar_return_slot) {
                result = Some(NestedResult::Scalar(loaded));
            } else {
                body_ok = false;
            }
        }

        // Restore outer scope regardless of outcome so the program
        // state stays sane even when a nested lift bails out.
        self.nested_result = outer_result;
        self.nested_return_slot = outer_return_slot;
        self.nested_end_label = outer_end_label;
        self.nested_array_return_slot = outer_array_return_slot;
        self.nested_depth -= 1;
        self.halted = outer_halted;
        self.locals = outer_locals;
        self.const_locals = outer_const;
        self.arrays = outer_arrays;

        if !body_ok {
            // Rewind builder body, const pool, register / signal /
            // slot counters, and label state to the pre-call point so
            // a fallback path sees a builder bit-identical to before
            // the attempt.
            self.builder.restore(pre_call_snapshot);
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
