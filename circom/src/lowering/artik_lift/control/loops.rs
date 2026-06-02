use artik::Reg;

use crate::ast::{BinOp, CompoundOp, Expr, Stmt};

use super::super::helpers::{
    collect_array_decls, collect_mutated_scalars, eval_const_expr, is_decrement_on,
    is_increment_on, stmts_have_return,
};
use super::super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Top-level `for` dispatcher. Tries the unroll path first; if
    /// the unroll would emit more registers than the executor's
    /// frame-size cap can hold, rolls back the builder and falls
    /// through to the runtime-while path. Bounds that don't fold
    /// compile-time also fall through to runtime.
    ///
    /// The rollback is the tricky bit: a partial unroll attempt
    /// leaves instructions and register allocations in the builder,
    /// and the runtime path would emit its own loop on top of that
    /// junk. The dispatch snapshots the builder state before the
    /// unroll and restores on bail.
    pub(in super::super) fn lift_for_dispatch(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        let snapshot = self.builder.snapshot();
        let saved_locals = self.locals.clone();
        let saved_const_locals = self.const_locals.clone();
        let saved_arrays = self.arrays.clone();
        if let Some(()) = self.lift_for_unrolled(init, condition, step, body) {
            return Some(());
        }
        // Unroll either bailed structurally or grew the frame past
        // the cap. Restore the snapshot so the runtime emit starts
        // from a clean slate.
        self.builder.restore(snapshot);
        self.locals = saved_locals;
        self.const_locals = saved_const_locals;
        self.arrays = saved_arrays;
        self.lift_for_runtime(init, condition, step, body)
    }

    /// Unroll a for loop at lift time. Loops with literal bounds and
    /// either a unit-increment (`++` / `+= 1`) ascending step or a
    /// unit-decrement (`--` / `-= 1`) descending step are supported.
    /// The loop variable is tracked as a `ConstInt` in `const_locals`
    /// for the duration of each body invocation; compile-time
    /// references to it fold to `PushConst`.
    pub(in super::super) fn lift_for_unrolled(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        // Init: `var <name> = <literal>;`
        let Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } = init
        else {
            return None;
        };
        if names.len() != 1 {
            return None;
        }
        let var_name = names[0].clone();
        let start = eval_const_expr(init_expr, &self.const_locals)?;

        // Step direction: ascending (`++` / `+= 1`) or descending
        // (`--` / `-= 1`). Determined first so the condition arm
        // below can pair correctly.
        enum Direction {
            Ascending,
            Descending,
        }
        let direction = match step {
            Stmt::Expr { expr, .. } => {
                if is_increment_on(expr, &var_name) {
                    Direction::Ascending
                } else if is_decrement_on(expr, &var_name) {
                    Direction::Descending
                } else {
                    return None;
                }
            }
            Stmt::CompoundAssign {
                target, op, value, ..
            } => {
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                if eval_const_expr(value, &self.const_locals)? != 1 {
                    return None;
                }
                match op {
                    CompoundOp::Add => Direction::Ascending,
                    CompoundOp::Sub => Direction::Descending,
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Condition shape pairs with direction:
        //   ascending  + `<var> < B`  → `start..B`
        //   ascending  + `<var> <= B` → `start..=B` (i.e. `B+1` exclusive)
        //   descending + `<var> > B`  → iterate `start..B` reversed (B exclusive lower bound)
        //   descending + `<var> >= B` → iterate `start..=B` reversed
        let (lo, hi_exclusive) = match condition {
            Expr::BinOp { op, lhs, rhs, .. } => {
                let Expr::Ident { name, .. } = lhs.as_ref() else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                let bound = eval_const_expr(rhs, &self.const_locals)?;
                match (&direction, op) {
                    (Direction::Ascending, BinOp::Lt) => (start, bound),
                    (Direction::Ascending, BinOp::Le) => (start, bound + 1),
                    (Direction::Descending, BinOp::Gt) => (bound + 1, start + 1),
                    (Direction::Descending, BinOp::Ge) => (bound, start + 1),
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Cheap bound on unroll work: the executor's frame size is
        // capped at MAX_FRAME_SIZE (65536 regs); each body iteration
        // can touch several registers. Reject loops beyond a safe
        // ceiling so a hostile circom source can't force the lift to
        // allocate a huge Artik body up front.
        let iterations = hi_exclusive.saturating_sub(lo);
        if !(0..=4096).contains(&iterations) {
            return None;
        }

        // Unroll. Iteration order follows the step direction so the
        // body sees the loop variable monotonically — required for
        // `var pieces[100][100]` patterns where prior iterations
        // populate cells the current iteration reads.
        let prev = self.const_locals.insert(var_name.clone(), start);
        let iter: Box<dyn Iterator<Item = ConstInt>> = match direction {
            Direction::Ascending => Box::new(lo..hi_exclusive),
            Direction::Descending => Box::new((lo..hi_exclusive).rev()),
        };
        // Frame-size budget: the executor caps each program at
        // `MAX_FRAME_SIZE = 65536` registers. A heavy unroll that
        // inlines large callees per iter (e.g. `mod_exp`'s outer
        // loop calling `prod` and `long_div`) blows past this in
        // tens of iterations. Bail early once the running register
        // count crosses 90 % of the cap so the dispatcher can roll
        // back and retry via the runtime-while path.
        const FRAME_BUDGET: u32 = 60_000;
        for i in iter {
            *self
                .const_locals
                .get_mut(&var_name)
                .expect("loop var was just inserted") = i;
            for stmt in body {
                self.lift_stmt(stmt)?;
                if self.halted {
                    break;
                }
            }
            if self.halted {
                break;
            }
            if self.builder.next_reg() > FRAME_BUDGET {
                return None;
            }
        }
        match prev {
            Some(v) => {
                self.const_locals.insert(var_name, v);
            }
            None => {
                self.const_locals.remove(&var_name);
            }
        }
        Some(())
    }

    /// Emit a `while` as `place(start); cond; jump_if_zero end; body;
    /// jump start; place(end);`. Mutable scalars whose values must
    /// flow across iterations are promoted to 1-element heap slots —
    /// reload at top, store at tail.
    pub(in super::super) fn lift_while(&mut self, condition: &Expr, body: &[Stmt]) -> Option<()> {
        let summary = collect_mutated_scalars(body);

        if summary.writes_witness {
            return None;
        }
        if stmts_have_return(body) {
            return None;
        }

        // Hoist `var arr[N]` declarations out of the loop body. The
        // body's `temp = call(...)` rebinds via call-return on every
        // iteration, so the alloc itself is wasted work — but emitted
        // per-iter under a runtime while it accumulates fresh
        // allocations and the heap explodes. Pre-allocate once before
        // the loop_start label, register names in `arrays`, and mark
        // each as hoisted; the body's VarDecl handler then skips the
        // re-allocation. Required by `mod_exp`'s pattern of declaring
        // `var temp[200]` and `var temp2[2][100]` inside if-blocks.
        let mut newly_hoisted: Vec<String> = Vec::new();
        if summary.declares_array {
            let mut decls: Vec<&Stmt> = Vec::new();
            collect_array_decls(body, &mut decls);
            // Dedupe by name: the same `var temp[200]` may be declared
            // in several branches (e.g. mod_exp's two if-blocks both
            // declare it). Allocate once for the first occurrence and
            // skip the rest.
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for decl in decls {
                let Stmt::VarDecl { names, .. } = decl else {
                    continue;
                };
                let Some(n) = names.first() else { continue };
                if !seen.insert(n.clone()) {
                    continue;
                }
                self.lift_stmt(decl)?;
                if let Some(shape) = self.arrays.get(n).copied() {
                    self.hoisted_arrays.insert(n.clone(), shape);
                    newly_hoisted.push(n.clone());
                }
            }
        }

        let mut promoted: Vec<(String, Reg)> = Vec::new();
        for name in &summary.scalars {
            if summary.fresh_decls.contains(name) {
                continue;
            }
            if self.const_locals.contains_key(name) {
                return None;
            }
            if let Some(initial) = self.locals.get(name).copied() {
                let slot = self.alloc_field_slot();
                self.store_field_slot(slot, initial)?;
                promoted.push((name.clone(), slot));
            }
        }

        let loop_start = self.builder.new_label();
        let loop_end = self.builder.new_label();

        self.builder.place(loop_start);

        for (name, slot) in &promoted {
            let reg = self.load_field_slot(*slot)?;
            self.locals.insert(name.clone(), reg);
        }

        let cond_reg = self.lift_expr(condition)?;
        let zero = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(cond_reg, zero);
        self.builder.jump_if_to(is_zero_int, loop_end);

        let lift_result: Option<()> = (|| {
            for stmt in body {
                self.lift_stmt(stmt)?;
                if self.halted {
                    return None;
                }
            }
            Some(())
        })();

        // Drop hoisted entries before propagating an outer error so the
        // enclosing scope doesn't see leaked bindings. Restoring the
        // declared shape into `arrays` here would mask later live-shape
        // queries; leaving the rebound shape is fine because the next
        // iteration's hoisted-skip check consults `hoisted_arrays`,
        // not `arrays`, for its size match.
        for n in &newly_hoisted {
            self.hoisted_arrays.remove(n);
        }
        lift_result?;

        for (name, slot) in &promoted {
            let cur = self.locals.get(name).copied()?;
            self.store_field_slot(*slot, cur)?;
        }

        self.builder.jump_to(loop_start);
        self.builder.place(loop_end);

        for (name, slot) in &promoted {
            let reg = self.load_field_slot(*slot)?;
            self.locals.insert(name.clone(), reg);
        }

        Some(())
    }

    /// A descending unit-decrement loop counting down to and including
    /// zero — `for (var i = START; i >= 0; i--)` or the equivalent
    /// `i > -1`. Naively desugaring this to `while (i >= 0) { body;
    /// i-- }` is unsound: `i >= 0` is a tautology for an unsigned /
    /// field counter, so after `i == 0` the decrement underflows to
    /// the field value `p - 1` and the loop runs on with a wrapped
    /// counter (garbage array indices, wrong witness, silently). circom
    /// fully unrolls these (the bound is morally constant); the runtime
    /// path is reached only when the unroll bailed or overflowed the
    /// frame cap, and it must still be correct.
    ///
    /// Returns the loop's `(var, start_expr)` if it has this shape.
    /// Matches *exactly* `for (var i = START; i >= 0; i--) BODY` (and the
    /// `i > -1` spelling) with a unit decrement — the shape circomlib uses
    /// for descending bigint passes. The scope is deliberately narrow:
    /// other descending forms (non-unit decrement `i -= 2`, or a positive
    /// inclusive lower bound `i >= K` for `K > 0` that the counter can step
    /// past) do *not* match and fall through to the generic runtime-`while`
    /// path, which is still tautological for a field counter (the canonical
    /// residue always satisfies the bound) and would underflow the same way.
    /// Those are the same silent-landmine class; left uncovered intentionally
    /// until a real circuit exercises one, at which point the rewrite
    /// generalises here rather than the pathology being rediscovered
    /// downstream.
    fn descending_to_zero(
        &self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
    ) -> Option<(String, Expr)> {
        let Stmt::VarDecl {
            names,
            init: Some(start_expr),
            ..
        } = init
        else {
            return None;
        };
        let [var_name] = names.as_slice() else {
            return None;
        };

        let descending = match step {
            Stmt::Expr { expr, .. } => is_decrement_on(expr, var_name),
            Stmt::CompoundAssign {
                target,
                op: CompoundOp::Sub,
                value,
                ..
            } => {
                matches!(target, Expr::Ident { name, .. } if name == var_name)
                    && eval_const_expr(value, &self.const_locals) == Some(1)
            }
            _ => false,
        };
        if !descending {
            return None;
        }

        let Expr::BinOp { op, lhs, rhs, .. } = condition else {
            return None;
        };
        if !matches!(lhs.as_ref(), Expr::Ident { name, .. } if name == var_name) {
            return None;
        }
        let bound = eval_const_expr(rhs, &self.const_locals)?;
        // Lower-inclusive bound of exactly zero: `i >= 0` or `i > -1`.
        let counts_down_to_zero = matches!((op, bound), (BinOp::Ge, 0) | (BinOp::Gt, -1));
        if !counts_down_to_zero {
            return None;
        }
        Some((var_name.clone(), start_expr.clone()))
    }

    /// Runtime fallback for `for` when the bounds are not literal:
    /// emit `init`, then a `while (cond)` whose body is `body; step;`.
    pub(in super::super) fn lift_for_runtime(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        if let Some((var_name, start_expr)) = self.descending_to_zero(init, condition, step) {
            // Rewrite `for (i = START; i >= 0; i--) BODY` into the
            // terminating, underflow-free equivalent
            //   i = START + 1;
            //   while (i != 0) { i = i - 1; BODY }
            // which runs BODY for i = START, START-1, ..., 0 and exits
            // when the top-of-loop test sees i == 0 — `i != 0` is not a
            // tautology, and the counter never steps below zero. All of
            // `lift_while`'s slot-promotion / array-hoist machinery is
            // reused unchanged.
            let span = start_expr.span().clone();
            let one = Expr::Number {
                value: "1".to_string(),
                span: span.clone(),
            };
            let new_init = Stmt::VarDecl {
                names: vec![var_name.clone()],
                dimensions: Vec::new(),
                init: Some(Expr::BinOp {
                    op: BinOp::Add,
                    lhs: Box::new(start_expr),
                    rhs: Box::new(one.clone()),
                    span: span.clone(),
                }),
                span: span.clone(),
            };
            let dec = Stmt::CompoundAssign {
                target: Expr::Ident {
                    name: var_name.clone(),
                    span: span.clone(),
                },
                op: CompoundOp::Sub,
                value: one,
                span: span.clone(),
            };
            let cond_ne_zero = Expr::BinOp {
                op: BinOp::Neq,
                lhs: Box::new(Expr::Ident {
                    name: var_name,
                    span: span.clone(),
                }),
                rhs: Box::new(Expr::Number {
                    value: "0".to_string(),
                    span: span.clone(),
                }),
                span,
            };
            let mut rewritten: Vec<Stmt> = Vec::with_capacity(body.len() + 1);
            rewritten.push(dec);
            rewritten.extend_from_slice(body);
            self.lift_stmt(&new_init)?;
            return self.lift_while(&cond_ne_zero, &rewritten);
        }
        self.lift_stmt(init)?;
        let mut combined: Vec<Stmt> = body.to_vec();
        combined.push(step.clone());
        self.lift_while(condition, &combined)
    }
}
