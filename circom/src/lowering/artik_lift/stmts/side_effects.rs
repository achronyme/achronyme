use artik::ElemT;

use crate::ast::{Expr, PostfixOp};

use super::super::helpers::eval_const_expr;
use super::super::{ArrayShape, LiftState};

impl<'f> LiftState<'f> {
    /// Mutate either `const_locals` or `locals` if `expr` is a
    /// supported side-effect form (postfix / prefix `++` or `--` on
    /// a tracked variable). Compile-time vars stay folded; runtime
    /// registers get a field-arithmetic update via `fadd` / `fsub`
    /// against the constant `1`. Returns `None` for shapes that
    /// don't fit either path.
    pub(super) fn apply_side_effect(&mut self, expr: &Expr) -> Option<()> {
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
    pub(in super::super) fn materialize_row_slice(
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
