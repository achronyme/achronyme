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
use super::{LiftState, NestedResult, ReturnShape};

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

                // Array declaration: `var arr[N];` — allocate backing
                // storage once, at the declaration site. Multi-dim
                // arrays (`[N][M]`) are out of scope for this release.
                //
                // Two init shapes are honored:
                //   - no init (`var arr[N];`) — leave the backing
                //     store empty; the body must write to it before
                //     reading.
                //   - array literal (`var arr[N] = [e0, e1, ...];`) —
                //     lift each element into a field register at
                //     declaration time and emit a StoreArr. Needed by
                //     circomlib SHA-256 (`var k[64] = [0x..., ...]`
                //     inside `sha256K`).
                //
                // Non-literal initializers (e.g. `var a[n] = b;`
                // aliasing another array) still bail to the inliner.
                if !dimensions.is_empty() {
                    if dimensions.len() != 1 {
                        return None;
                    }
                    let size = eval_const_expr(&dimensions[0], &self.const_locals)?;
                    if !(0..=i64::from(u32::MAX)).contains(&size) {
                        return None;
                    }
                    let len = size as u32;
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

                    self.arrays.insert(name.clone(), (handle, len));
                    return Some(());
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
                // Indexed assignment: `arr[i] = expr`. Supported when
                // `arr` is a declared array and `i` folds to a
                // compile-time index in bounds.
                if let Expr::Index { object, index, .. } = target {
                    let Expr::Ident { name, .. } = object.as_ref() else {
                        return None;
                    };
                    let (arr_reg, len) = self.arrays.get(name).copied()?;
                    let idx = eval_const_expr(index, &self.const_locals)?;
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
                if let Expr::Index { object, index, .. } = target {
                    let Expr::Ident { name, .. } = object.as_ref() else {
                        return None;
                    };
                    let (arr_reg, len) = self.arrays.get(name).copied()?;
                    let idx = eval_const_expr(index, &self.const_locals)?;
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
            } => self.lift_for(init, condition, step, &body.stmts),
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
                if let Expr::Ident { name, .. } = value {
                    if let Some(&(arr_reg, len)) = self.arrays.get(name) {
                        if self.nested_depth > 0 {
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

                // Scalar return.
                let r = self.lift_expr(value)?;
                if self.nested_depth > 0 {
                    self.nested_result = Some(NestedResult::Scalar(r));
                    self.halted = true;
                    return Some(());
                }
                let slot = self.builder.alloc_witness_slot();
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

    /// Mutate `const_locals` if `expr` is a supported side-effect form
    /// (postfix / prefix `++` or `--` on a compile-time-tracked var).
    /// Returns `None` for anything else, which falls back to E212.
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
        // Only compile-time-tracked vars support ++/--: a runtime
        // `i++` would require loading, adding 1, storing, which the
        // lift can support later but does not today.
        let current = self.const_locals.get(name).copied()?;
        let next = match op {
            PostfixOp::Increment => current.checked_add(1)?,
            PostfixOp::Decrement => current.checked_sub(1)?,
        };
        self.const_locals.insert(name.clone(), next);
        Some(())
    }
}
