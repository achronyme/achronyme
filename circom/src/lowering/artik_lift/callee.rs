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

use artik::Reg;

use crate::ast::FunctionDef;

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
