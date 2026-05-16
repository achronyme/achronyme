//! Callee-subprogram scope management for the subprogram witness lift.
//!
//! A callee subprogram is lifted as a pass over the shared builder
//! that is separate from the entry-body pass: its parameters arrive as
//! `Call` argument registers (not signals), and it returns via
//! `Return` (not witness slots). [`LiftState::begin_callee_body`] swaps
//! the lift's name scopes for a fresh one bound to those argument
//! registers; [`LiftState::end_callee_body`] restores the swapped-out
//! scope. The swap mirrors the scope discipline the inlining path
//! already uses, but the parameter source is the call arguments rather
//! than freshly read input signals.

use std::collections::HashMap;

use artik::{ElemT, Reg};

use crate::ast::{Expr, FunctionDef};

use super::{ArrayShape, ConstInt, LiftState};

/// How one callee parameter is supplied by the call site. A scalar is
/// the argument register (plus its compile-time value when the caller
/// passed a constant, so dimension folds and `1 << n`-style patterns
/// resolve inside the body); an array is the handle into the shared
/// global array store.
pub(super) enum CalleeParamBinding {
    Scalar {
        reg: Reg,
        const_val: Option<ConstInt>,
    },
    Array(ArrayShape),
}

/// The lift scopes swapped out by [`LiftState::begin_callee_body`],
/// restored verbatim by [`LiftState::end_callee_body`]. Holding it by
/// value makes the begin/end pair impossible to misuse — the only way
/// to restore is to feed back the token the begin returned.
pub(super) struct SavedScope {
    locals: HashMap<String, Reg>,
    const_locals: HashMap<String, ConstInt>,
    arrays: HashMap<String, ArrayShape>,
    halted: bool,
}

impl LiftState<'_> {
    /// Enter a callee body: swap the current name scopes out and bind
    /// the callee's parameters to the supplied argument bindings.
    /// Returns `None` (leaving the scope untouched) when the binding
    /// count does not match the callee's parameter count.
    pub(super) fn begin_callee_body(
        &mut self,
        callee: &FunctionDef,
        bindings: &[CalleeParamBinding],
    ) -> Option<SavedScope> {
        if bindings.len() != callee.params.len() {
            return None;
        }
        let saved = SavedScope {
            locals: std::mem::take(&mut self.locals),
            const_locals: std::mem::take(&mut self.const_locals),
            arrays: std::mem::take(&mut self.arrays),
            halted: self.halted,
        };
        self.halted = false;
        for (param, binding) in callee.params.iter().zip(bindings) {
            match binding {
                CalleeParamBinding::Scalar { reg, const_val } => {
                    self.locals.insert(param.clone(), *reg);
                    if let Some(v) = const_val {
                        self.const_locals.insert(param.clone(), *v);
                    }
                }
                CalleeParamBinding::Array(shape) => {
                    self.arrays.insert(param.clone(), *shape);
                }
            }
        }
        Some(saved)
    }

    /// Leave a callee body, restoring the scope that
    /// [`Self::begin_callee_body`] swapped out.
    pub(super) fn end_callee_body(&mut self, saved: SavedScope) {
        self.locals = saved.locals;
        self.const_locals = saved.const_locals;
        self.arrays = saved.arrays;
        self.halted = saved.halted;
    }

    /// Emit a callee subprogram's `return <value>;` as a single
    /// `Return` instruction. Every return shape collapses to exactly
    /// one register: a scalar is the value register; any array — a
    /// named local, a 2D row slice, or an array literal — is the one
    /// handle into the global array store (arrays cross the
    /// `Call`/`Return` boundary by handle, so there is no per-cell
    /// witness-slot marshalling here). This is the simplification the
    /// subprogram path buys over the inlining path's slot/label dance.
    pub(super) fn emit_callee_return(&mut self, value: &Expr) -> Option<()> {
        // `return out;` where `out` is a live array local.
        if let Expr::Ident { name, .. } = value {
            if let Some(&shape) = self.arrays.get(name) {
                let handle = shape.handle();
                self.builder.ret_vals(&[handle]);
                self.halted = true;
                return Some(());
            }
        }

        // `return arr2d[row];` — materialize the row, return its handle.
        if let Expr::Index { object, index, .. } = value {
            if let Expr::Ident { name, .. } = object.as_ref() {
                if let Some(ArrayShape::Flat2D {
                    handle: src_handle,
                    rows,
                    cols,
                }) = self.arrays.get(name).copied()
                {
                    let row_shape = self.materialize_row_slice(src_handle, rows, cols, index)?;
                    let handle = match row_shape {
                        ArrayShape::Flat1D { handle, .. } => handle,
                        ArrayShape::Flat2D { .. } => return None,
                    };
                    self.builder.ret_vals(&[handle]);
                    self.halted = true;
                    return Some(());
                }
            }
        }

        // `return [e0, e1, ...];` — build the array, return its handle.
        if let Expr::ArrayLit { elements, .. } = value {
            let len = u32::try_from(elements.len()).ok()?;
            let handle = self.builder.alloc_array(len, ElemT::Field);
            for (i, elem) in elements.iter().enumerate() {
                let val_reg = self.lift_expr(elem)?;
                let idx_reg = self.push_int_const(i as u64)?;
                self.builder.store_arr(handle, idx_reg, val_reg);
            }
            self.builder.ret_vals(&[handle]);
            self.halted = true;
            return Some(());
        }

        // Scalar return.
        let r = self.lift_expr(value)?;
        self.builder.ret_vals(&[r]);
        self.halted = true;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Definition;
    use crate::parser::parse_circom;
    use std::collections::HashMap;

    #[test]
    fn callee_scope_binds_params_and_round_trips() {
        let src = "function probe(s, arr) { return s; }";
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let Definition::Function(callee) = &prog.definitions[0] else {
            panic!("expected function");
        };

        let functions: HashMap<String, &FunctionDef> = HashMap::new();
        let mut state = LiftState::new(&[], &[], &functions);

        // Outer scope the callee must not see, and must get back.
        state.locals.insert("outer".to_string(), 99);
        state.halted = true;

        let bindings = vec![
            CalleeParamBinding::Scalar {
                reg: 7,
                const_val: Some(5),
            },
            CalleeParamBinding::Array(ArrayShape::Flat1D { handle: 3, len: 4 }),
        ];

        let saved = state
            .begin_callee_body(callee, &bindings)
            .expect("arity matches");

        assert_eq!(state.locals.get("s"), Some(&7));
        assert_eq!(state.const_locals.get("s"), Some(&5));
        assert_eq!(
            state.arrays.get("arr").map(|a| a.as_1d()),
            Some(Some((3, 4)))
        );
        // Outer scope is hidden and the halt flag is reset for the body.
        assert!(!state.locals.contains_key("outer"));
        assert!(!state.halted);

        state.end_callee_body(saved);

        assert_eq!(state.locals.get("outer"), Some(&99));
        assert!(!state.locals.contains_key("s"));
        assert!(!state.arrays.contains_key("arr"));
        assert!(state.halted);
    }

    fn callee_subprogram_body(
        src: &str,
        sub_params: Vec<artik::RegType>,
        sub_returns: Vec<artik::RegType>,
        binding: CalleeParamBinding,
    ) -> Vec<artik::Instr> {
        use crate::lowering::artik_lift::driver::LiftDriver;

        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let Definition::Function(callee) = &prog.definitions[0] else {
            panic!("expected function");
        };

        let functions: HashMap<String, &FunctionDef> = HashMap::new();
        let mut state = LiftState::new(&[], &[], &functions);
        state.driver = Some(LiftDriver::new());

        let id = state.builder.reserve_subprogram(sub_params, sub_returns);
        let prev = state.builder.begin_subprogram(id);
        let saved = state
            .begin_callee_body(callee, &[binding])
            .expect("arity matches");
        for stmt in &callee.body.stmts {
            state.lift_stmt(stmt).expect("callee body lifts");
        }
        state.end_callee_body(saved);
        state.builder.end_subprogram(prev);

        let program = state.builder.finish().expect("builder finishes");
        program.subprograms[id as usize].body.clone()
    }

    #[test]
    fn scalar_callee_return_emits_ret_vals_not_witness() {
        let body = callee_subprogram_body(
            "function probe(s) { return s; }",
            vec![artik::RegType::Field],
            vec![artik::RegType::Field],
            CalleeParamBinding::Scalar {
                reg: 0,
                const_val: None,
            },
        );
        // Parameter `s` is the pre-allocated param register 0; the
        // return forwards it as a single Return source.
        assert!(
            matches!(body.last(), Some(artik::Instr::Return { srcs }) if srcs == &vec![0]),
            "expected `Return {{ srcs: [0] }}`, got {:?}",
            body.last()
        );
        assert!(
            !body
                .iter()
                .any(|i| matches!(i, artik::Instr::WriteWitness { .. })),
            "a callee subprogram must not write witness slots"
        );
    }

    #[test]
    fn array_callee_return_returns_the_handle() {
        let body = callee_subprogram_body(
            "function probe(arr) { return arr; }",
            vec![artik::RegType::Array(ElemT::Field)],
            vec![artik::RegType::Array(ElemT::Field)],
            CalleeParamBinding::Array(ArrayShape::Flat1D { handle: 0, len: 3 }),
        );
        // The array crosses the boundary as its handle register (0),
        // not as per-cell witness writes.
        assert!(
            matches!(body.last(), Some(artik::Instr::Return { srcs }) if srcs == &vec![0]),
            "expected `Return {{ srcs: [0] }}`, got {:?}",
            body.last()
        );
        assert!(
            !body
                .iter()
                .any(|i| matches!(i, artik::Instr::WriteWitness { .. })),
            "an array callee return must not write witness slots"
        );
    }

    #[test]
    fn arity_mismatch_leaves_scope_untouched() {
        let src = "function probe(a, b) { return a; }";
        let (prog, _) = parse_circom(src).expect("parse failed");
        let Definition::Function(callee) = &prog.definitions[0] else {
            panic!("expected function");
        };

        let functions: HashMap<String, &FunctionDef> = HashMap::new();
        let mut state = LiftState::new(&[], &[], &functions);
        state.locals.insert("outer".to_string(), 1);

        let bindings = vec![CalleeParamBinding::Scalar {
            reg: 0,
            const_val: None,
        }];
        assert!(state.begin_callee_body(callee, &bindings).is_none());
        // Scope is intact — the early return must not have swapped.
        assert_eq!(state.locals.get("outer"), Some(&1));
    }
}
