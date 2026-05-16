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

use artik::{ElemT, IntW};

use crate::ast::{BinOp, Expr, PostfixOp, Stmt};

use super::bytecode::PeelLhs;
use super::helpers::{compound_to_binop, eval_const_expr};
use super::{ArrayShape, LiftState, ReturnShape};

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

                        // The enclosing `lift_while` may have hoisted
                        // this name out of the loop body to avoid
                        // re-allocating on every iteration. The
                        // pre-walk emitted the AllocArray once and
                        // recorded the *declared* shape in
                        // `hoisted_arrays`; the body's re-encounter
                        // is a no-op as long as the declaration's
                        // length matches the originally-hoisted
                        // shape. (The live entry in `arrays` may be
                        // shorter after a `temp = call(...)` rebind
                        // shrunk the slot, but the hoisted shape
                        // tracks the declaration size.)
                        if let Some(hoisted_shape) = self.hoisted_arrays.get(name).copied() {
                            if init.is_some() {
                                return None;
                            }
                            if let ArrayShape::Flat1D {
                                len: hoisted_len, ..
                            } = hoisted_shape
                            {
                                if hoisted_len == len {
                                    return Some(());
                                }
                            }
                            return None;
                        }

                        // Call-returning-array init: `var sumAndCarry[2]
                        // = SplitFn(...)`. Three shapes:
                        //   - exact match (`len == val_len`): alias the
                        //     callee's handle directly.
                        //   - declared larger (`val_len < len`): copy
                        //     the call's elements into a fresh
                        //     `len`-cell allocation. Reads past
                        //     `val_len` hit the lift's
                        //     out-of-bounds-returns-zero path. Required
                        //     by `short_div`'s
                        //     `var norm_a[200] = long_scalar_mult(...)`
                        //     where the callee returns `100` cells and
                        //     the caller declares `200`.
                        //   - declared smaller: bail.
                        if let Some(Expr::Call { callee, args, .. }) = init {
                            let (val_handle, val_len) =
                                self.lift_call_returning_array(callee, args)?;
                            if val_len > len {
                                return None;
                            }
                            if val_len == len {
                                self.arrays.insert(
                                    name.clone(),
                                    ArrayShape::Flat1D {
                                        handle: val_handle,
                                        len,
                                    },
                                );
                            } else {
                                let dst_handle = self.builder.alloc_array(len, ElemT::Field);
                                for i in 0..val_len {
                                    let src_idx = self.push_int_const(i as u64)?;
                                    let val_reg = self.builder.load_arr(val_handle, src_idx);
                                    let dst_idx = self.push_int_const(i as u64)?;
                                    self.builder.store_arr(dst_handle, dst_idx, val_reg);
                                }
                                self.arrays.insert(
                                    name.clone(),
                                    ArrayShape::Flat1D {
                                        handle: dst_handle,
                                        len,
                                    },
                                );
                            }
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
                        let rows_i = eval_const_expr(&dimensions[0], &self.const_locals)?;
                        let cols_i = eval_const_expr(&dimensions[1], &self.const_locals)?;
                        if !(0..=i64::from(u32::MAX)).contains(&rows_i)
                            || !(0..=i64::from(u32::MAX)).contains(&cols_i)
                        {
                            return None;
                        }
                        let rows = rows_i as u32;
                        let cols = cols_i as u32;

                        // Hoisted by an enclosing `lift_while` — see
                        // the 1D branch above.
                        if let Some(hoisted_shape) = self.hoisted_arrays.get(name).copied() {
                            if init.is_some() {
                                return None;
                            }
                            if let ArrayShape::Flat2D {
                                rows: hoisted_rows,
                                cols: hoisted_cols,
                                ..
                            } = hoisted_shape
                            {
                                if hoisted_rows == rows && hoisted_cols == cols {
                                    return Some(());
                                }
                            }
                            return None;
                        }

                        // Call-returning-2D-array init: alias the
                        // callee's returned handle directly, mirroring
                        // the 1D Call-init path. Required by
                        // `mod_exp`'s `var temp2[2][100] = long_div(...)`.
                        if let Some(Expr::Call { callee, args, .. }) = init {
                            let (val_handle, val_rows, val_cols) =
                                self.lift_call_returning_array_2d(callee, args)?;
                            if val_rows != rows || val_cols != cols {
                                return None;
                            }
                            self.arrays.insert(
                                name.clone(),
                                ArrayShape::Flat2D {
                                    handle: val_handle,
                                    rows,
                                    cols,
                                },
                            );
                            return Some(());
                        }

                        if init.is_some() {
                            // 2D literal init not yet implemented —
                            // bigint witness funcs always declare
                            // uninitialized 2D arrays and fill via
                            // indexed writes.
                            return None;
                        }
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
                    if let Some(idx) = eval_const_expr(outer_idx, &self.const_locals) {
                        // Compile-time index: an out-of-range write is
                        // unconditionally a bug — the lift bails.
                        if !(0..i64::from(len)).contains(&idx) {
                            return None;
                        }
                        let idx_reg = self.push_int_const(idx as u64)?;
                        let val_reg = self.lift_expr(value)?;
                        self.builder.store_arr(arr_reg, idx_reg, val_reg);
                        return Some(());
                    }
                    // Runtime index (e.g. a while-promoted loop counter):
                    // lift the index expression into a field register,
                    // then IntFromField U32 into the int register
                    // StoreArr expects — the mirror of the runtime-index
                    // read path. The executor traps on out-of-bounds
                    // access, so the bounds check is deferred rather than
                    // duplicated here.
                    let idx_field = self.lift_expr(outer_idx)?;
                    let idx_reg = self.builder.int_from_field(IntW::U32, idx_field);
                    let val_reg = self.lift_expr(value)?;
                    self.builder.store_arr(arr_reg, idx_reg, val_reg);
                    return Some(());
                }
                let Expr::Ident { name, .. } = target else {
                    return None;
                };

                // Whole-array reassignment from a call: `name = call(...)`
                // where `name` was previously declared as an array and
                // the callee returns an array of matching shape. Re-bind
                // the array slot to the callee's returned handle —
                // arrays live on the Artik heap, so this is a handle
                // swap, not a per-element copy. Required by `long_div`'s
                // `remainder = long_sub(...)` and `mod_exp`'s
                // `temp2 = long_div(...)` shapes.
                // 1D row-slice assignment: `out = arr2d[r]` where the
                // RHS is a 2D array indexed by a compile-time-foldable
                // row index. Emit a per-element copy from the row's
                // flat range into the destination 1D slot. Required by
                // `mod_exp`'s `out = temp2[1]` shape, where the body
                // pulls one row of the long_div quotient/remainder
                // tuple back into a 1D running accumulator.
                if let Some(ArrayShape::Flat1D {
                    handle: dst_handle,
                    len: dst_len,
                }) = self.arrays.get(name).copied()
                {
                    if let Expr::Index {
                        object: src_obj,
                        index: src_idx,
                        ..
                    } = value
                    {
                        if let Expr::Ident { name: src_name, .. } = src_obj.as_ref() {
                            if let Some(ArrayShape::Flat2D {
                                handle: src_handle,
                                rows,
                                cols,
                            }) = self.arrays.get(src_name).copied()
                            {
                                let row_const = eval_const_expr(src_idx, &self.const_locals)?;
                                if !(0..i64::from(rows)).contains(&row_const) {
                                    return None;
                                }
                                let row_base = (row_const as u32) * cols;
                                let copy_len = dst_len.min(cols);
                                for j in 0..copy_len {
                                    let src_idx_reg = self.push_int_const((row_base + j) as u64)?;
                                    let val_reg = self.builder.load_arr(src_handle, src_idx_reg);
                                    let dst_idx_reg = self.push_int_const(j as u64)?;
                                    self.builder.store_arr(dst_handle, dst_idx_reg, val_reg);
                                }
                                return Some(());
                            }
                        }
                    }
                }

                if let Some(target_shape) = self.arrays.get(name).copied() {
                    if let Expr::Call { callee, args, .. } = value {
                        match target_shape {
                            ArrayShape::Flat1D {
                                len: target_len, ..
                            } => {
                                let (val_handle, val_len) =
                                    self.lift_call_returning_array(callee, args)?;
                                // Allow shrinking rebind (callee
                                // returns fewer cells than the slot was
                                // declared with): the new logical view
                                // is the callee's return; reads past
                                // the smaller length hit the
                                // out-of-bounds-returns-zero path.
                                // Required by `long_div`'s
                                // `remainder = long_sub(...)` shape
                                // (slot is 200, callee returns 100).
                                if val_len > target_len {
                                    return None;
                                }
                                self.arrays.insert(
                                    name.clone(),
                                    ArrayShape::Flat1D {
                                        handle: val_handle,
                                        len: val_len,
                                    },
                                );
                                return Some(());
                            }
                            ArrayShape::Flat2D {
                                rows: target_rows,
                                cols: target_cols,
                                ..
                            } => {
                                let (val_handle, val_rows, val_cols) =
                                    self.lift_call_returning_array_2d(callee, args)?;
                                if val_rows != target_rows || val_cols != target_cols {
                                    return None;
                                }
                                self.arrays.insert(
                                    name.clone(),
                                    ArrayShape::Flat2D {
                                        handle: val_handle,
                                        rows: target_rows,
                                        cols: target_cols,
                                    },
                                );
                                return Some(());
                            }
                        }
                    }
                }

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
                        let new_val = self.lift_field_binop(binop, PeelLhs::Reg(cur), value)?;
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
                    let new_val = self.lift_field_binop(binop, PeelLhs::Reg(cur), value)?;
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
                let r = self.lift_field_binop(binop, PeelLhs::Reg(lhs_reg), value)?;
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
                // A callee subprogram returns by value: one `Return`
                // instruction carrying a single register. The entry
                // subprogram (active id 0) keeps the witness-slot ABI
                // below.
                if self.builder.active_subprogram() != 0 {
                    return self.emit_callee_return(value);
                }
                // Array-return for the entry function: expose each
                // element as its own witness slot so the caller can
                // re-bundle them into a `CircuitNode::LetArray`. 2D
                // arrays return their flattened row-major layout
                // (`rows * cols` slots).
                if let Expr::Ident { name, .. } = value {
                    if let Some(&shape) = self.arrays.get(name) {
                        let len = shape.total_len();
                        let arr_reg = shape.handle();
                        let slots = match self.output_array_slots.as_ref() {
                            Some(s) if s.len() == len as usize => s.clone(),
                            Some(_) => return None,
                            None => {
                                let s: Vec<u32> = (0..len)
                                    .map(|_| self.builder.alloc_witness_slot())
                                    .collect();
                                self.output_array_slots = Some(s.clone());
                                s
                            }
                        };
                        for (i, slot) in slots.iter().copied().enumerate() {
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

                // Row-slice return: `return arr2d[row_idx];` where the
                // local is a Flat2D and the row index const-folds.
                // Materialize the row as a fresh Flat1D and fall
                // through to the 1D array-return path (per-cell witness
                // slots or `NestedResult::Array`). Shape lookup happens
                // on the syntactic base name; a chained `arr2d[r][c]`
                // would shape-match the inner index and fall through to
                // the scalar path further down, which is the correct
                // behaviour for a fully-indexed read.
                if let Expr::Index { object, index, .. } = value {
                    if let Expr::Ident { name, .. } = object.as_ref() {
                        if let Some(ArrayShape::Flat2D {
                            handle: src_handle,
                            rows,
                            cols,
                        }) = self.arrays.get(name).copied()
                        {
                            let row_shape =
                                self.materialize_row_slice(src_handle, rows, cols, index)?;
                            let (dst_handle, len) = match row_shape {
                                ArrayShape::Flat1D { handle, len } => (handle, len),
                                ArrayShape::Flat2D { .. } => return None,
                            };
                            let slots = match self.output_array_slots.as_ref() {
                                Some(s) if s.len() == len as usize => s.clone(),
                                Some(_) => return None,
                                None => {
                                    let s: Vec<u32> = (0..len)
                                        .map(|_| self.builder.alloc_witness_slot())
                                        .collect();
                                    self.output_array_slots = Some(s.clone());
                                    s
                                }
                            };
                            for (i, slot) in slots.iter().copied().enumerate() {
                                let idx_reg = self.push_int_const(i as u64)?;
                                let val_reg = self.builder.load_arr(dst_handle, idx_reg);
                                self.builder.write_witness(slot, val_reg);
                            }
                            self.builder.ret();
                            self.halted = true;
                            self.return_shape = ReturnShape::Array(len);
                            return Some(());
                        }
                    }
                }

                // Array-literal return: `return [e0, e1, ..., eN];`.
                // Allocate a fresh 1D field array, lift each element
                // into a register, store at index `i`. From there the
                // path is identical to a named-array return — outer
                // functions emit per-cell witness slots. Nested calls
                // take a shorter route: the destination is the
                // pre-allocated `nested_array_return_slot` so every
                // return in the body writes into the same heap array
                // and jumps to the shared end-label, leaving the
                // caller observing whichever return actually fired
                // at runtime.
                if let Expr::ArrayLit { elements, .. } = value {
                    let len_usize = elements.len();
                    let len = u32::try_from(len_usize).ok()?;
                    let handle = self.builder.alloc_array(len, ElemT::Field);
                    for (i, elem) in elements.iter().enumerate() {
                        let val_reg = self.lift_expr(elem)?;
                        let idx_reg = self.push_int_const(i as u64)?;
                        self.builder.store_arr(handle, idx_reg, val_reg);
                    }
                    let slots = match self.output_array_slots.as_ref() {
                        Some(s) if s.len() == len as usize => s.clone(),
                        Some(_) => return None,
                        None => {
                            let s: Vec<u32> = (0..len)
                                .map(|_| self.builder.alloc_witness_slot())
                                .collect();
                            self.output_array_slots = Some(s.clone());
                            s
                        }
                    };
                    for (i, slot) in slots.iter().copied().enumerate() {
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
            Stmt::Assert { arg, .. } => {
                // Asserts inside a witness function are advisory checks
                // — they abort witness computation on failure but emit
                // no constraints. The Artik VM has no assert opcode, so
                // the lift evaluates the predicate at compile time:
                // a const-true predicate is dropped, a const-false
                // predicate bails so the caller surfaces an explicit
                // gap, and a runtime-valued predicate also bails so a
                // semantic the function relied on is not silently
                // skipped. Circomlib's witness functions invariably
                // gate on shape parameters (`n == 64 && k == 4`) which
                // fold cleanly under `try_eval_arg_const` at the call
                // site.
                let v = eval_const_expr(arg, &self.const_locals)?;
                if v == 0 {
                    return None;
                }
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

    // Materialize a single row of a Flat2D source as a fresh Flat1D
    // array. Used when a row slice (`arr[r]`) flows into a position
    // that requires a standalone 1D array — return value of a function
    // body, or array argument to a nested call. The row index must
    // const-fold; runtime row indices would need a copy loop, deferred
    // until a circomlib template exercises that shape.
    pub(super) fn materialize_row_slice(
        &mut self,
        src_handle: artik::Reg,
        rows: u32,
        cols: u32,
        row_idx_expr: &Expr,
    ) -> Option<ArrayShape> {
        let row_const = eval_const_expr(row_idx_expr, &self.const_locals)?;
        if !(0..i64::from(rows)).contains(&row_const) {
            return None;
        }
        let row_base = (row_const as u32) * cols;
        let dst_handle = self.builder.alloc_array(cols, ElemT::Field);
        for j in 0..cols {
            let src_idx_reg = self.push_int_const((row_base + j) as u64)?;
            let val_reg = self.builder.load_arr(src_handle, src_idx_reg);
            let dst_idx_reg = self.push_int_const(j as u64)?;
            self.builder.store_arr(dst_handle, dst_idx_reg, val_reg);
        }
        Some(ArrayShape::Flat1D {
            handle: dst_handle,
            len: cols,
        })
    }
}
