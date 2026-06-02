use artik::ElemT;

use crate::ast::Expr;

use super::super::helpers::eval_const_expr;
use super::super::{ArrayShape, LiftState};

impl<'f> LiftState<'f> {
    pub(super) fn lift_var_decl(
        &mut self,
        names: &[String],
        dimensions: &[Expr],
        init: &Option<Expr>,
    ) -> Option<()> {
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
                    let (val_handle, val_len) = self.lift_call_returning_array(callee, args)?;
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
}
