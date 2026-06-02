use memory::{FieldBackend, FieldElement};

use super::super::utils::fe_to_u64;
use super::super::{InstEnvValue, Instantiator, MAX_INSTANTIATE_ITERATIONS};
use crate::error::ProveIrError;
use crate::types::*;

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_for(
        &mut self,
        var: &str,
        range: &ForRange,
        body: &[CircuitNode],
    ) -> Result<(), ProveIrError> {
        match range {
            ForRange::Literal { start, end } => self.emit_range_loop(var, *start, *end, body),
            ForRange::WithCapture { start, end_capture } => {
                let end_fe = self.captures.get(end_capture).ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing capture value for loop bound `{end_capture}`"
                        ),
                        span: None,
                    }
                })?;
                let end = fe_to_u64(end_fe, end_capture)?;
                self.emit_range_loop(var, *start, end, body)
            }
            ForRange::WithExpr { start, end_expr } => {
                let end = self.eval_const_expr_u64(end_expr)?;
                self.emit_range_loop(var, *start, end, body)
            }
            ForRange::Array(arr_name) => {
                let elems = match self.env.get(arr_name) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("for loop iterable `{arr_name}` is not an array"),
                            span: None,
                        });
                    }
                };

                self.with_saved_var(var, |this| {
                    for elem_var in &elems {
                        this.env
                            .insert(var.to_string(), InstEnvValue::Scalar(*elem_var));
                        for node in body {
                            this.emit_node(node)?;
                        }
                    }
                    Ok(())
                })
            }
        }
    }
    /// Unroll a numeric range loop: `for var in start..end { body }`.
    ///
    /// Two emission strategies:
    ///
    /// 1. **Eager unroll** — when [`Self::body_is_const_tractable`]
    ///    proves every expression in `body` would resolve via
    ///    [`Self::eval_const_expr`] under `var = Const(i)`, the loop
    ///    is fully unrolled at instantiate time. Each iteration binds
    ///    `var` to a fresh `Const(i)` SSA, so downstream fast paths
    ///    in `emit_shift_dispatch` / BitAnd-Or-Xor fold the entire
    ///    iteration body to constants without emitting Decompose /
    ///    SymbolicShift chains. This is the path that closes the
    ///    SHA-256 outer-wrapper +N c-per-input-bit residual.
    ///
    /// 2. **Symbolic loop** (fallback) — allocate one fresh SSA slot
    ///    for `var`, switch the sink to a sub-buffer via
    ///    [`InstrSink::begin_symbolic_loop`], emit body **once** with
    ///    `var` symbolically bound to that slot, then close with
    ///    [`InstrSink::finish_symbolic_loop`] which folds the
    ///    sub-buffer into a single
    ///    [`ExtendedInstruction::LoopUnroll`] in the outer scope.
    ///    The Lysis lifter's executor handles the per-iteration
    ///    value binding at run time — needed for bodies that read
    ///    signal arrays or contain non-const-foldable operations.
    fn emit_range_loop(
        &mut self,
        var: &str,
        start: u64,
        end: u64,
        body: &[CircuitNode],
    ) -> Result<(), ProveIrError> {
        let iterations = end.saturating_sub(start);
        if iterations > MAX_INSTANTIATE_ITERATIONS {
            return Err(ProveIrError::RangeTooLarge {
                iterations,
                max: MAX_INSTANTIATE_ITERATIONS,
                span: None,
            });
        }

        // Eager-unroll path: bind `var` to Const(i) per iteration so
        // every read inside the body resolves to a constant via
        // env + const_value_of, letting `eval_const_expr` fold the
        // entire iteration body without materialising Decompose /
        // SymbolicShift IR.
        if self.body_is_const_tractable(body, var) {
            return self.with_saved_var(var, |this| {
                for i in start..end {
                    let const_v = this.emit_const(FieldElement::<F>::from_u64(i));
                    this.env
                        .insert(var.to_string(), InstEnvValue::Scalar(const_v));
                    for node in body {
                        this.emit_node(node)?;
                    }
                }
                Ok(())
            });
        }

        // Symbolic-loop fallback. Allocate iter_var BEFORE the body,
        // in the outer scope, so the LoopUnroll node refers to a slot
        // declared in the parent's namespace (the executor's loop
        // machinery binds it per iteration there).
        let iter_var = self.fresh_var();
        if self.keeps_metadata() {
            self.set_name(iter_var, var.to_string());
        }
        self.sink.begin_symbolic_loop();
        let result = self.with_saved_var(var, |this| {
            this.env
                .insert(var.to_string(), InstEnvValue::Scalar(iter_var));
            for node in body {
                this.emit_node(node)?;
            }
            Ok(())
        });
        self.sink
            .finish_symbolic_loop(iter_var, start as i64, end as i64);
        result
    }

    /// True iff `body` would emit only constant SSAs / pure constraint
    /// statements when `iter_var` is bound to a `Const(i)` SSA in env.
    /// Bias is toward false negatives: the predicate may say "no" on a
    /// body that would in fact fold (missing an optimization) but must
    /// never say "yes" on a body that emits Decompose / SymbolicShift /
    /// witness Inputs (which would silently break the symbolic-loop
    /// invariant the walker relies on).
    pub(in crate::instantiate) fn body_is_const_tractable(
        &self,
        body: &[CircuitNode],
        iter_var: &str,
    ) -> bool {
        body.iter()
            .all(|n| self.node_is_const_tractable(n, iter_var))
    }

    fn node_is_const_tractable(&self, node: &CircuitNode, iter_var: &str) -> bool {
        match node {
            CircuitNode::AssertEq { lhs, rhs, .. } => {
                self.expr_is_const_tractable(lhs, iter_var)
                    && self.expr_is_const_tractable(rhs, iter_var)
            }
            CircuitNode::Assert { expr, .. } | CircuitNode::Expr { expr, .. } => {
                self.expr_is_const_tractable(expr, iter_var)
            }
            CircuitNode::LetIndexed { index, value, .. } => {
                self.expr_is_const_tractable(index, iter_var)
                    && self.expr_is_const_tractable(value, iter_var)
            }
            CircuitNode::If {
                cond,
                then_body,
                else_body,
                ..
            } => {
                self.expr_is_const_tractable(cond, iter_var)
                    && self.body_is_const_tractable(then_body, iter_var)
                    && self.body_is_const_tractable(else_body, iter_var)
            }
            // Conservative: nested loops, let-bindings, witness
            // declarations, decomposes, gadget calls — all introduce
            // SSA shapes that intra-iter forward-flow analysis would
            // need to track. Falling back to symbolic for these is
            // safe and covers the wrapper-loop case without the
            // analysis surface.
            CircuitNode::For { .. }
            | CircuitNode::Let { .. }
            | CircuitNode::LetArray { .. }
            | CircuitNode::Decompose { .. }
            | CircuitNode::WitnessHint { .. }
            | CircuitNode::WitnessArrayDecl { .. }
            | CircuitNode::WitnessHintIndexed { .. }
            | CircuitNode::WitnessCall { .. }
            | CircuitNode::ComponentCall { .. } => false,
        }
    }

    fn expr_is_const_tractable(&self, expr: &CircuitExpr, iter_var: &str) -> bool {
        match expr {
            CircuitExpr::Const(_) => true,
            CircuitExpr::Capture(name) => self.captures.contains_key(name),
            CircuitExpr::Var(name) | CircuitExpr::Input(name) => {
                if name == iter_var {
                    return true;
                }
                matches!(
                    self.env.get(name),
                    Some(InstEnvValue::Scalar(ssa)) if self.const_value_of(*ssa).is_some()
                )
            }
            CircuitExpr::BinOp { lhs, rhs, .. }
            | CircuitExpr::IntDiv { lhs, rhs, .. }
            | CircuitExpr::IntMod { lhs, rhs, .. }
            | CircuitExpr::BitAnd { lhs, rhs, .. }
            | CircuitExpr::BitOr { lhs, rhs, .. }
            | CircuitExpr::BitXor { lhs, rhs, .. }
            | CircuitExpr::Comparison { lhs, rhs, .. }
            | CircuitExpr::BoolOp { lhs, rhs, .. } => {
                self.expr_is_const_tractable(lhs, iter_var)
                    && self.expr_is_const_tractable(rhs, iter_var)
            }
            CircuitExpr::ShiftR { operand, shift, .. }
            | CircuitExpr::ShiftL { operand, shift, .. } => {
                self.expr_is_const_tractable(operand, iter_var)
                    && self.expr_is_const_tractable(shift, iter_var)
            }
            CircuitExpr::UnaryOp { operand, .. } | CircuitExpr::BitNot { operand, .. } => {
                self.expr_is_const_tractable(operand, iter_var)
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => {
                self.expr_is_const_tractable(cond, iter_var)
                    && self.expr_is_const_tractable(if_true, iter_var)
                    && self.expr_is_const_tractable(if_false, iter_var)
            }
            CircuitExpr::Pow { base, .. } => self.expr_is_const_tractable(base, iter_var),
            CircuitExpr::ArrayLen(name) => {
                matches!(self.env.get(name), Some(InstEnvValue::Array(_)))
            }
            CircuitExpr::ArrayIndex { array, index } => {
                if !self.expr_is_const_tractable(index, iter_var) {
                    return false;
                }
                match self.env.get(array) {
                    Some(InstEnvValue::Array(elems)) => {
                        elems.iter().all(|&ssa| self.const_value_of(ssa).is_some())
                    }
                    _ => false,
                }
            }
            CircuitExpr::PoseidonHash { .. }
            | CircuitExpr::PoseidonMany(_)
            | CircuitExpr::RangeCheck { .. }
            | CircuitExpr::MerkleVerify { .. }
            | CircuitExpr::LoopVar(_) => false,
        }
    }

    /// Save a variable's env binding, run a closure, then restore it.
    fn with_saved_var<Func>(&mut self, var: &str, f: Func) -> Result<(), ProveIrError>
    where
        Func: FnOnce(&mut Self) -> Result<(), ProveIrError>,
    {
        let saved = self.env.get(var).cloned();
        let result = f(self);
        match saved {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }
        result
    }
}
