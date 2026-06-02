use artik::IntW;

use crate::ast::Expr;

use super::super::helpers::eval_const_expr;
use super::super::{ArrayShape, LiftState};

impl<'f> LiftState<'f> {
    pub(super) fn lift_substitution(&mut self, target: &Expr, value: &Expr) -> Option<()> {
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
                let flat_idx_reg = self.flatten_2d_index(inner_idx, outer_idx, rows, cols)?;
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
                        let (val_handle, val_len) = self.lift_call_returning_array(callee, args)?;
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
}
