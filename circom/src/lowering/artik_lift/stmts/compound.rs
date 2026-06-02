use crate::ast::{BinOp, CompoundOp, Expr};

use super::super::bytecode::PeelLhs;
use super::super::helpers::{compound_to_binop, eval_const_expr};
use super::super::{ArrayShape, LiftState};

impl<'f> LiftState<'f> {
    pub(super) fn lift_compound_assign(
        &mut self,
        target: &Expr,
        op: CompoundOp,
        value: &Expr,
    ) -> Option<()> {
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
        let binop = compound_to_binop(op)?;
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
                let flat_idx_reg = self.flatten_2d_index(inner_idx, outer_idx, rows, cols)?;
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
}
