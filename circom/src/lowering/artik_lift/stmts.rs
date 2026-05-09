//! Statement lift.
//!
//! [`LiftState::lift_stmt`] is the entry point: a 4-arm dispatcher over
//! `VarDecl`, `Substitution`, `CompoundAssign`, `For`, `IfElse`, `Return`,
//! and `Expr` (the bare-expression statement form, used for postfix /
//! prefix increments on loop variables).
//!
//! [`LiftState::apply_side_effect`] handles the bare-expression
//! statement: it mutates the compile-time `const_locals` entry for `i++`
//! / `++i` / `i--` / `--i` over a tracked variable, and rejects any
//! other shape.

use artik::ElemT;

use crate::ast::{BinOp, Expr, PostfixOp, Stmt};

use super::helpers::{compound_to_binop, eval_const_expr};
use super::{ArrayShape, LiftState, NestedResult, ReturnShape};

impl<'f> LiftState<'f> {
    pub(super) fn lift_stmt(&mut self, stmt: &Stmt) -> Option<()> {
        if self.halted {
            return Some(());
        }
        match stmt {
            Stmt::VarDecl {
                names,
                dimensions,
                init,
                ..
            } => {
                // Tuple destructuring (`var (a, b) = ...`) is out of
                // scope — would need to unpack multiple return values.
                if names.len() != 1 {
                    return None;
                }
                let name = &names[0];

                // Array declaration. 1D and 2D shapes are honored;
                // dim ≥ 3 is out of scope. The two-dim case flattens
                // row-major into a single Artik array of `rows*cols`
                // cells.
                //
                // Two init shapes are honored on 1D arrays:
                //   - no init (`var arr[N];`) — leave the backing
                //     store empty; the body must write to it before
                //     reading.
                //   - array literal (`var arr[N] = [e0, e1, ...];`) —
                //     lift each element into a field register at
                //     declaration time and emit a StoreArr. Needed by
                //     circomlib SHA-256 (`var k[64] = [0x..., ...]`
                //     inside `sha256K`).
                //
                // 2D arrays (`var arr[N][M];`) require a non-init
                // shape — initialized 2D literals are not yet supported.
                // Non-literal initializers (e.g. `var a[n] = b;`
                // aliasing another array) still bail to the inliner.
                if !dimensions.is_empty() {
                    if dimensions.len() == 1 {
                        let size = eval_const_expr(&dimensions[0], &self.const_locals)?;
                        if !(0..=i64::from(u32::MAX)).contains(&size) {
                            return None;
                        }
                        let len = size as u32;

                        // Call-returning-array init: `var sumAndCarry[2]
                        // = SplitFn(...)`. The callee already allocated
                        // its own backing array on the heap and handed
                        // back a handle via `NestedResult::Array`.
                        // Alias the handle directly — no fresh
                        // `AllocArray`, no per-element copy.
                        if let Some(Expr::Call { callee, args, .. }) = init {
                            let (val_handle, val_len) =
                                self.lift_call_returning_array(callee, args)?;
                            if val_len != len {
                                return None;
                            }
                            self.arrays.insert(
                                name.clone(),
                                ArrayShape::Flat1D {
                                    handle: val_handle,
                                    len,
                                },
                            );
                            return Some(());
                        }

                        let handle = self.builder.alloc_array(len, ElemT::Field);

                        if let Some(init_expr) = init {
                            let Expr::ArrayLit { elements, .. } = init_expr else {
                                return None;
                            };
                            if usize::try_from(len).ok()? != elements.len() {
                                return None;
                            }
                            for (i, elem) in elements.iter().enumerate() {
                                let val_reg = self.lift_expr(elem)?;
                                let idx_reg = self.push_int_const(i as u64)?;
                                self.builder.store_arr(handle, idx_reg, val_reg);
                            }
                        }

                        self.arrays
                            .insert(name.clone(), ArrayShape::Flat1D { handle, len });
                        return Some(());
                    }
                    if dimensions.len() == 2 {
                        if init.is_some() {
                            // 2D literal init not yet implemented —
                            // bigint witness funcs always declare
                            // uninitialized 2D arrays and fill via
                            // indexed writes.
                            return None;
                        }
                        let rows_i = eval_const_expr(&dimensions[0], &self.const_locals)?;
                        let cols_i = eval_const_expr(&dimensions[1], &self.const_locals)?;
                        if !(0..=i64::from(u32::MAX)).contains(&rows_i)
                            || !(0..=i64::from(u32::MAX)).contains(&cols_i)
                        {
                            return None;
                        }
                        let rows = rows_i as u32;
                        let cols = cols_i as u32;
                        let total = rows.checked_mul(cols)?;
                        let handle = self.builder.alloc_array(total, ElemT::Field);
                        self.arrays
                            .insert(name.clone(), ArrayShape::Flat2D { handle, rows, cols });
                        return Some(());
                    }
                    return None;
                }

                let Some(expr) = init else {
                    // Uninitialized scalar `var x;` declares the name
                    // without a backing register — the body must
                    // assign to it via a Substitution before any use.
                    return Some(());
                };
                let r = self.lift_expr(expr)?;
                self.locals.insert(name.clone(), r);
                // An initialized var never lives in `const_locals` —
                // if an older iteration of the enclosing loop left a
                // compile-time entry, evict it so reads pick up the
                // new runtime register.
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::Substitution { target, value, .. } => {
                // 2D indexed assignment: `arr[i][j] = expr`. Detected
                // by a nested-Index AST shape. Both indices may be
                // compile-time or runtime; the lift composes the flat
                // index `i * cols + j` accordingly.
                if let Expr::Index {
                    object: outer_obj,
                    index: outer_idx,
                    ..
                } = target
                {
                    if let Expr::Index {
                        object: inner_obj,
                        index: inner_idx,
                        ..
                    } = outer_obj.as_ref()
                    {
                        let Expr::Ident { name, .. } = inner_obj.as_ref() else {
                            return None;
                        };
                        let shape = self.arrays.get(name).copied()?;
                        let (handle, rows, cols) = match shape {
                            ArrayShape::Flat2D { handle, rows, cols } => (handle, rows, cols),
                            ArrayShape::Flat1D { .. } => return None,
                        };
                        let flat_idx_reg =
                            self.flatten_2d_index(inner_idx, outer_idx, rows, cols)?;
                        let val_reg = self.lift_expr(value)?;
                        self.builder.store_arr(handle, flat_idx_reg, val_reg);
                        return Some(());
                    }

                    let Expr::Ident { name, .. } = outer_obj.as_ref() else {
                        return None;
                    };
                    let target_shape = self.arrays.get(name).copied()?;

                    // Whole-row 2D assignment: `split[i] = call(...)`
                    // where `split` is 2D and the call returns a 1D
                    // array of length matching `cols`. The returned
                    // handle's elements are copied into the row at
                    // offset `i * cols`. `i` must fold compile-time so
                    // the row offset is a literal.
                    if let ArrayShape::Flat2D {
                        handle: dst_handle,
                        rows,
                        cols,
                    } = target_shape
                    {
                        let Expr::Call { callee, args, .. } = value else {
                            return None;
                        };
                        let (val_handle, val_len) = self.lift_call_returning_array(callee, args)?;
                        if val_len != cols {
                            return None;
                        }
                        let i_const = eval_const_expr(outer_idx, &self.const_locals)?;
                        if !(0..i64::from(rows)).contains(&i_const) {
                            return None;
                        }
                        let row_base = (i_const as u32) * cols;
                        for j in 0..cols {
                            let src_idx = self.push_int_const(j as u64)?;
                            let val_reg = self.builder.load_arr(val_handle, src_idx);
                            let dst_idx = self.push_int_const((row_base + j) as u64)?;
                            self.builder.store_arr(dst_handle, dst_idx, val_reg);
                        }
                        return Some(());
                    }

                    // 1D indexed assignment: `arr[i] = expr`.
                    let (arr_reg, len) = target_shape.as_1d()?;
                    let idx = eval_const_expr(outer_idx, &self.const_locals)?;
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    let idx_reg = self.push_int_const(idx as u64)?;
                    let val_reg = self.lift_expr(value)?;
                    self.builder.store_arr(arr_reg, idx_reg, val_reg);
                    return Some(());
                }
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                let r = self.lift_expr(value)?;
                self.locals.insert(name.clone(), r);
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::CompoundAssign {
                target, op, value, ..
            } => {
                // Compound assignment: `x += expr`, `x *= expr`, etc.
                // Rewrite as `x = x <op> expr` and route through the
                // normal expression lift. If `x` is a compile-time
                // loop variable and `expr` folds to a constant, we
                // prefer to mutate `const_locals` so downstream
                // lookups keep folding — otherwise the variable
                // transitions to a runtime register.
                //
                // Indexed target (`arr[i] += expr`): supported when
                // `arr` is a declared array. Required by circomlib
                // SHA-256's `H[i] += hin[i*32+j] << j` and
                // `w[i] += inp[i*32+31-j] << j` accumulators.
                let binop = compound_to_binop(*op)?;
                if let Expr::Index {
                    object: outer_obj,
                    index: outer_idx,
                    ..
                } = target
                {
                    // 2D compound assignment: `arr[i][j] op= expr`.
                    if let Expr::Index {
                        object: inner_obj,
                        index: inner_idx,
                        ..
                    } = outer_obj.as_ref()
                    {
                        let Expr::Ident { name, .. } = inner_obj.as_ref() else {
                            return None;
                        };
                        let shape = self.arrays.get(name).copied()?;
                        let (handle, rows, cols) = match shape {
                            ArrayShape::Flat2D { handle, rows, cols } => (handle, rows, cols),
                            ArrayShape::Flat1D { .. } => return None,
                        };
                        let flat_idx_reg =
                            self.flatten_2d_index(inner_idx, outer_idx, rows, cols)?;
                        let cur = self.builder.load_arr(handle, flat_idx_reg);
                        let rhs_reg = self.lift_expr(value)?;
                        let new_val = self.apply_field_binop(binop, cur, rhs_reg)?;
                        self.builder.store_arr(handle, flat_idx_reg, new_val);
                        return Some(());
                    }

                    let Expr::Ident { name, .. } = outer_obj.as_ref() else {
                        return None;
                    };
                    let (arr_reg, len) = self.arrays.get(name).copied()?.as_1d()?;
                    let idx = eval_const_expr(outer_idx, &self.const_locals)?;
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    let idx_reg = self.push_int_const(idx as u64)?;
                    let cur = self.builder.load_arr(arr_reg, idx_reg);
                    let rhs_reg = self.lift_expr(value)?;
                    let new_val = self.apply_field_binop(binop, cur, rhs_reg)?;
                    self.builder.store_arr(arr_reg, idx_reg, new_val);
                    return Some(());
                }
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                if let Some(current) = self.const_locals.get(name).copied() {
                    if let Some(rhs_const) = eval_const_expr(value, &self.const_locals) {
                        let folded = match binop {
                            BinOp::Add => current.checked_add(rhs_const),
                            BinOp::Sub => current.checked_sub(rhs_const),
                            BinOp::Mul => current.checked_mul(rhs_const),
                            _ => None,
                        };
                        if let Some(v) = folded {
                            self.const_locals.insert(name.clone(), v);
                            return Some(());
                        }
                    }
                }
                let lhs_reg = self.lookup_ident(name)?;
                let rhs_reg = self.lift_expr(value)?;
                let r = self.apply_field_binop(binop, lhs_reg, rhs_reg)?;
                self.locals.insert(name.clone(), r);
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
                ..
            } => self.lift_for_dispatch(init, condition, step, &body.stmts),
            Stmt::While {
                condition, body, ..
            } => self.lift_while(condition, &body.stmts),
            Stmt::IfElse {
                condition,
                then_body,
                else_body,
                ..
            } => self.lift_if_else(condition, then_body, else_body.as_ref()),
            Stmt::Return { value, .. } => {
                // Array-return: `return <local_array>;` — for the
                // outer function, expose each element as its own
                // witness slot so the caller can re-bundle them into
                // a `CircuitNode::LetArray`. For a nested inlined
                // call, hand the array handle back to the caller's
                // lift_expr via `nested_result` — no slot allocation.
                //
                // 2D arrays return their flattened layout (row-major,
                // `rows * cols` slots). The caller side is responsible
                // for re-bundling into a 2D shape if needed; for a
                // nested call, only the 1D return path is supported
                // today (2D nested-return would need NestedResult to
                // carry the (rows, cols) tuple — Phase 4 territory).
                if let Expr::Ident { name, .. } = value {
                    if let Some(&shape) = self.arrays.get(name) {
                        let len = shape.total_len();
                        let arr_reg = shape.handle();
                        if self.nested_depth > 0 {
                            // Nested-call return — only 1D supported
                            // today. 2D nested return is Phase 4.
                            if !matches!(shape, ArrayShape::Flat1D { .. }) {
                                return None;
                            }
                            self.nested_result = Some(NestedResult::Array(arr_reg, len));
                            self.halted = true;
                            return Some(());
                        }
                        for i in 0..len {
                            let slot = self.builder.alloc_witness_slot();
                            let idx_reg = self.push_int_const(i as u64)?;
                            let val_reg = self.builder.load_arr(arr_reg, idx_reg);
                            self.builder.write_witness(slot, val_reg);
                        }
                        self.builder.ret();
                        self.halted = true;
                        self.return_shape = ReturnShape::Array(len);
                        return Some(());
                    }
                }

                // Array-literal return: `return [e0, e1, ..., eN];`.
                // Allocate a fresh 1D field array, lift each element
                // into a register, store at index `i`. From there the
                // path is identical to a named-array return — nested
                // calls get a NestedResult::Array handle, outer
                // functions emit per-cell witness slots.
                if let Expr::ArrayLit { elements, .. } = value {
                    let len_usize = elements.len();
                    let len = u32::try_from(len_usize).ok()?;
                    let handle = self.builder.alloc_array(len, ElemT::Field);
                    for (i, elem) in elements.iter().enumerate() {
                        let val_reg = self.lift_expr(elem)?;
                        let idx_reg = self.push_int_const(i as u64)?;
                        self.builder.store_arr(handle, idx_reg, val_reg);
                    }
                    if self.nested_depth > 0 {
                        self.nested_result = Some(NestedResult::Array(handle, len));
                        self.halted = true;
                        return Some(());
                    }
                    for i in 0..len {
                        let slot = self.builder.alloc_witness_slot();
                        let idx_reg = self.push_int_const(i as u64)?;
                        let val_reg = self.builder.load_arr(handle, idx_reg);
                        self.builder.write_witness(slot, val_reg);
                    }
                    self.builder.ret();
                    self.halted = true;
                    self.return_shape = ReturnShape::Array(len);
                    return Some(());
                }

                // Scalar return.
                let r = self.lift_expr(value)?;
                if self.nested_depth > 0 {
                    self.nested_result = Some(NestedResult::Scalar(r));
                    self.halted = true;
                    return Some(());
                }
                let slot = match self.output_slot {
                    Some(s) => s,
                    None => {
                        let s = self.builder.alloc_witness_slot();
                        self.output_slot = Some(s);
                        s
                    }
                };
                self.builder.write_witness(slot, r);
                self.builder.ret();
                self.halted = true;
                self.return_shape = ReturnShape::Scalar;
                Some(())
            }
            Stmt::Expr { expr, .. } => {
                // Bare expression statement. Only supported when it's
                // a postfix/prefix increment/decrement on a loop var —
                // the actual value is discarded; the side effect
                // mutates the const_locals entry. This is what lets
                // `for (; ; i++)` round-trip cleanly when the loop is
                // unrolled via `lift_for`.
                self.apply_side_effect(expr)
            }
            _ => None,
        }
    }

    /// Mutate either `const_locals` or `locals` if `expr` is a
    /// supported side-effect form (postfix / prefix `++` or `--` on
    /// a tracked variable). Compile-time vars stay folded; runtime
    /// registers get a field-arithmetic update via `fadd` / `fsub`
    /// against the constant `1`. Returns `None` for shapes that
    /// don't fit either path.
    fn apply_side_effect(&mut self, expr: &Expr) -> Option<()> {
        let (op, operand) = match expr {
            Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => {
                (op, operand)
            }
            _ => return None,
        };
        let Expr::Ident { name, .. } = operand.as_ref() else {
            return None;
        };

        if let Some(current) = self.const_locals.get(name).copied() {
            let next = match op {
                PostfixOp::Increment => current.checked_add(1)?,
                PostfixOp::Decrement => current.checked_sub(1)?,
            };
            self.const_locals.insert(name.clone(), next);
            return Some(());
        }

        if let Some(reg) = self.locals.get(name).copied() {
            let one = self.push_const_unsigned(1)?;
            let new_reg = match op {
                PostfixOp::Increment => self.builder.fadd(reg, one),
                PostfixOp::Decrement => self.builder.fsub(reg, one),
            };
            self.locals.insert(name.clone(), new_reg);
            return Some(());
        }

        None
    }
}
