//! Per-statement decomposition of a circom function body into a
//! sequence of [`LiftFragment`]s.
//!
//! When the standard single-frame [`super::lift_function_to_artik`]
//! fails because the body exceeds the Artik register budget, this
//! path retries by treating each function call inside the body as
//! its own [`CircuitNode::WitnessCall`]. Non-call statements
//! (variable declarations, aliasing copies, literal-bound `for`
//! loops) update an in-memory binding map but do not emit fragments
//! — the function's return is then a re-bundling of those bindings
//! into the appropriate [`DecomposedResult`].
//!
//! The body shape recognised here is the linear chain found in
//! circomlib's curve-arithmetic helpers like
//! `secp256k1_addunequal_func`: a sequence of `var X[N] = call(...)`
//! statements, opening/closing aliasing loops, and a final `return`.
//! Anything else (conditionals, `while`, non-call init expressions
//! beyond simple aliasing) returns `None` so the caller surfaces the
//! original E212.

use std::collections::HashMap;

use diagnostics::Span;
use ir_forge::types::CircuitExpr;

use crate::ast::{AssignOp, BinOp, Expr, FunctionDef, PostfixOp, Stmt};
use crate::lowering::context::LoweringContext;

use super::helpers::eval_const_expr;
use super::{
    lift_function_to_artik, ConstInt, DecomposedLift, DecomposedResult, LiftFragment, LiftedShape,
    ParamShape,
};

/// Attempt to lift `func` by decomposing its body into a sequence of
/// per-call fragments. The caller is expected to have already tried
/// [`super::lift_function_to_artik`] and seen `None`; this is the
/// recovery path for bodies that overflow a single Artik frame.
///
/// `lowered_args` is the flat per-parameter CircuitExpr stream the
/// outer caller built (1 element per scalar param, N elements per
/// `Array(N)` param). The order matches `param_shapes`.
pub fn try_lift_via_decomposition(
    _function_name: &str,
    func: &FunctionDef,
    param_shapes: &[(String, ParamShape)],
    param_consts: &[Option<ConstInt>],
    lowered_args: &[CircuitExpr],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<DecomposedLift> {
    let mut state = DecomposeState::new(ctx, span.clone());
    state.seed_params(param_shapes, param_consts, lowered_args)?;

    for stmt in &func.body.stmts {
        state.walk_stmt(stmt)?;
        if state.returned.is_some() {
            break;
        }
    }

    let result = state.returned.take()?;
    Some(DecomposedLift {
        fragments: state.fragments,
        result,
    })
}

struct DecomposeState<'ctx, 'src> {
    ctx: &'src mut LoweringContext<'ctx>,
    span: Span,
    scalars: HashMap<String, CircuitExpr>,
    arr1d: HashMap<String, Vec<CircuitExpr>>,
    arr2d: HashMap<String, Array2D>,
    const_vars: HashMap<String, ConstInt>,
    fragments: Vec<LiftFragment>,
    returned: Option<DecomposedResult>,
}

struct Array2D {
    rows: u32,
    cols: u32,
    /// Row-major flat: cell (r, c) at `r * cols + c`.
    cells: Vec<CircuitExpr>,
}

impl<'ctx, 'src> DecomposeState<'ctx, 'src> {
    fn new(ctx: &'src mut LoweringContext<'ctx>, span: Span) -> Self {
        Self {
            ctx,
            span,
            scalars: HashMap::new(),
            arr1d: HashMap::new(),
            arr2d: HashMap::new(),
            const_vars: HashMap::new(),
            fragments: Vec::new(),
            returned: None,
        }
    }

    fn seed_params(
        &mut self,
        param_shapes: &[(String, ParamShape)],
        param_consts: &[Option<ConstInt>],
        lowered_args: &[CircuitExpr],
    ) -> Option<()> {
        let mut offset = 0;
        for (i, (name, shape)) in param_shapes.iter().enumerate() {
            match shape {
                ParamShape::Scalar => {
                    let expr = lowered_args.get(offset)?.clone();
                    self.scalars.insert(name.clone(), expr);
                    offset += 1;
                    if let Some(Some(v)) = param_consts.get(i) {
                        self.const_vars.insert(name.clone(), *v);
                    }
                }
                ParamShape::Array(len) => {
                    let len_usize = *len as usize;
                    let mut cells = Vec::with_capacity(len_usize);
                    for j in 0..len_usize {
                        cells.push(lowered_args.get(offset + j)?.clone());
                    }
                    self.arr1d.insert(name.clone(), cells);
                    offset += len_usize;
                }
            }
        }
        Some(())
    }

    fn walk_stmt(&mut self, stmt: &Stmt) -> Option<()> {
        match stmt {
            Stmt::VarDecl {
                names,
                dimensions,
                init,
                ..
            } => self.handle_var_decl(names, dimensions, init.as_ref()),
            Stmt::Substitution {
                target,
                op: AssignOp::Assign,
                value,
                ..
            } => self.handle_assign(target, value),
            Stmt::For {
                init,
                condition,
                step,
                body,
                ..
            } => self.handle_for(init, condition, step, body),
            Stmt::Return { value, .. } => {
                self.returned = Some(self.resolve_return(value)?);
                Some(())
            }
            Stmt::Block(block) => {
                for s in &block.stmts {
                    self.walk_stmt(s)?;
                    if self.returned.is_some() {
                        break;
                    }
                }
                Some(())
            }
            _ => None,
        }
    }

    fn handle_var_decl(
        &mut self,
        names: &[String],
        dimensions: &[Expr],
        init: Option<&Expr>,
    ) -> Option<()> {
        if names.len() != 1 {
            return None;
        }
        let name = &names[0];

        match dimensions.len() {
            0 => {
                // Scalar local. If `init` is a const-foldable scalar
                // we also remember the value for loop-bound math.
                if let Some(expr) = init {
                    if let Some(v) = self.try_eval_const_scalar(expr) {
                        self.const_vars.insert(name.clone(), v);
                    }
                    let ce = self.resolve_scalar_expr(expr)?;
                    self.scalars.insert(name.clone(), ce);
                }
                Some(())
            }
            1 => {
                let len = self.fold_dim_to_u32(&dimensions[0])?;
                match init {
                    None => {
                        // Empty 1D — initialise with a placeholder
                        // Const(0) cell vector that aliasing
                        // assignments will overwrite. The cells stay
                        // Const(0) only if the function actually
                        // intends a zero-init (rare in this shape).
                        let zero = CircuitExpr::Const(zero_field());
                        let cells = vec![zero; len as usize];
                        self.arr1d.insert(name.clone(), cells);
                        Some(())
                    }
                    Some(init_expr) => {
                        // The only meaningful 1D init we support is a
                        // function call that returns a 1D array. Try
                        // to lift the call and bind each output to
                        // the new local's cells.
                        let cells = self.lift_call_returning_array(init_expr, len)?;
                        self.arr1d.insert(name.clone(), cells);
                        Some(())
                    }
                }
            }
            2 => {
                if init.is_some() {
                    // 2D inits beyond the empty decl are uncommon in
                    // the target body shape.
                    return None;
                }
                let rows = self.fold_dim_to_u32(&dimensions[0])?;
                let cols = self.fold_dim_to_u32(&dimensions[1])?;
                let zero = CircuitExpr::Const(zero_field());
                let cells = vec![zero; (rows as usize) * (cols as usize)];
                self.arr2d
                    .insert(name.clone(), Array2D { rows, cols, cells });
                Some(())
            }
            _ => None,
        }
    }

    fn handle_assign(&mut self, target: &Expr, value: &Expr) -> Option<()> {
        // Supported targets:
        //   X[i]          → 1D cell write
        //   X[r][c]       → 2D cell write
        match target {
            Expr::Index { object, index, .. } => match object.as_ref() {
                Expr::Ident { name, .. } => {
                    let idx = self.fold_index(index)?;
                    let value_ce = self.resolve_scalar_expr(value)?;
                    let cells = self.arr1d.get_mut(name)?;
                    let slot = cells.get_mut(idx)?;
                    *slot = value_ce;
                    Some(())
                }
                Expr::Index {
                    object: inner_obj,
                    index: row_idx,
                    ..
                } => {
                    let row_name = match inner_obj.as_ref() {
                        Expr::Ident { name, .. } => name.clone(),
                        _ => return None,
                    };
                    let row = self.fold_index(row_idx)?;
                    let col = self.fold_index(index)?;
                    let value_ce = self.resolve_scalar_expr(value)?;
                    let arr = self.arr2d.get_mut(&row_name)?;
                    if (row as u32) >= arr.rows || (col as u32) >= arr.cols {
                        return None;
                    }
                    let flat = row * (arr.cols as usize) + col;
                    arr.cells[flat] = value_ce;
                    Some(())
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn handle_for(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &crate::ast::Block,
    ) -> Option<()> {
        // Recognise the canonical `for (var i = lo; i < hi; i++) { ... }`
        // shape, with `lo`, `hi` both const-foldable in the current
        // env. Anything else (variable step, mid-loop break,
        // condition that isn't `<`) bails.
        let (iter_name, lo) = match init {
            Stmt::VarDecl {
                names,
                init: Some(init_expr),
                ..
            } if names.len() == 1 => {
                let v = self.try_eval_const_scalar(init_expr)?;
                (names[0].clone(), v)
            }
            _ => return None,
        };

        let hi = match condition {
            Expr::BinOp {
                op: BinOp::Lt,
                lhs,
                rhs,
                ..
            } => match lhs.as_ref() {
                Expr::Ident { name, .. } if *name == iter_name => {
                    self.try_eval_const_scalar(rhs)?
                }
                _ => return None,
            },
            _ => return None,
        };

        match step {
            Stmt::Expr {
                expr:
                    Expr::PostfixOp {
                        op: PostfixOp::Increment,
                        operand,
                        ..
                    },
                ..
            } => match operand.as_ref() {
                Expr::Ident { name, .. } if *name == iter_name => {}
                _ => return None,
            },
            _ => return None,
        }

        for i in lo..hi {
            self.const_vars.insert(iter_name.clone(), i);
            for s in &body.stmts {
                self.walk_stmt(s)?;
                if self.returned.is_some() {
                    return Some(());
                }
            }
        }
        self.const_vars.remove(&iter_name);
        Some(())
    }

    /// Lift a function call as a fragment that returns a 1D array of
    /// `expected_len` cells. Each cell is a [`CircuitExpr::Var`]
    /// referencing one of the fragment's output bindings.
    fn lift_call_returning_array(
        &mut self,
        call_expr: &Expr,
        expected_len: u32,
    ) -> Option<Vec<CircuitExpr>> {
        let (callee_name, args) = match call_expr {
            Expr::Call { callee, args, .. } => match callee.as_ref() {
                Expr::Ident { name, .. } => (name.clone(), args.clone()),
                _ => return None,
            },
            _ => return None,
        };
        let func = *self.ctx.functions.get(callee_name.as_str())?;
        if func.params.len() != args.len() {
            return None;
        }

        // Classify each arg as scalar (one CircuitExpr) or array
        // (vec of CircuitExpr). The classification is driven by
        // whether the arg expression resolves to a name in `arr1d`
        // (or a row of `arr2d`), so the callee's parameter takes the
        // matching shape.
        let mut callee_param_shapes: Vec<(String, ParamShape)> =
            Vec::with_capacity(func.params.len());
        let mut callee_param_consts: Vec<Option<ConstInt>> = Vec::with_capacity(func.params.len());
        let mut callee_lowered_args: Vec<CircuitExpr> = Vec::new();

        for (arg, param_name) in args.iter().zip(func.params.iter()) {
            if let Some(cells) = self.resolve_arg_as_array(arg) {
                let len_u32 = u32::try_from(cells.len()).ok()?;
                callee_param_shapes.push((param_name.clone(), ParamShape::Array(len_u32)));
                callee_param_consts.push(None);
                callee_lowered_args.extend(cells);
            } else {
                let scalar = self.resolve_scalar_expr(arg)?;
                callee_param_shapes.push((param_name.clone(), ParamShape::Scalar));
                callee_param_consts.push(self.try_eval_const_scalar(arg));
                callee_lowered_args.push(scalar);
            }
        }

        let span_for_call = self.span.clone();
        let lifted = lift_function_to_artik(
            callee_name.as_str(),
            &callee_param_shapes,
            &callee_param_consts,
            &func.body.stmts,
            self.ctx,
            &span_for_call,
        )?;

        // We only handle 1D-returning callees here. Scalar returns
        // can't bind to a 1D destination; 2D returns would require a
        // separate path and aren't part of the secp256k1 chain.
        let lift_len = match lifted.shape {
            LiftedShape::Array(n) => n,
            _ => return None,
        };
        if lift_len != expected_len {
            return None;
        }

        let cells: Vec<CircuitExpr> = lifted
            .outputs
            .iter()
            .map(|n| CircuitExpr::Var(n.clone()))
            .collect();

        // Promote any nested fragments first so the parent's fragment
        // sees their bindings in `env`. Then push the parent itself.
        for frag in lifted.extra_fragments {
            self.fragments.push(frag);
        }
        self.fragments.push(LiftFragment {
            program_bytes: lifted.program_bytes,
            input_signals: callee_lowered_args,
            output_bindings: lifted.outputs,
        });

        Some(cells)
    }

    fn resolve_arg_as_array(&self, expr: &Expr) -> Option<Vec<CircuitExpr>> {
        match expr {
            Expr::Ident { name, .. } => self.arr1d.get(name).cloned(),
            Expr::Index { object, index, .. } => {
                // `arr2d[row]` row slice. The row index must
                // const-fold; the destination is the row's column
                // cells.
                let row = self.fold_index(index)?;
                match object.as_ref() {
                    Expr::Ident { name, .. } => {
                        let arr = self.arr2d.get(name)?;
                        if (row as u32) >= arr.rows {
                            return None;
                        }
                        let row_base = row * (arr.cols as usize);
                        Some(arr.cells[row_base..row_base + (arr.cols as usize)].to_vec())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn resolve_scalar_expr(&self, expr: &Expr) -> Option<CircuitExpr> {
        match expr {
            Expr::Ident { name, .. } => {
                if let Some(ce) = self.scalars.get(name) {
                    Some(ce.clone())
                } else {
                    self.const_vars
                        .get(name)
                        .map(|v| CircuitExpr::Const(field_from_i64(*v)))
                }
            }
            Expr::Number { value, .. } => {
                let v = value.parse::<i64>().ok()?;
                Some(CircuitExpr::Const(field_from_i64(v)))
            }
            Expr::Index { object, index, .. } => {
                let idx = self.fold_index(index)?;
                match object.as_ref() {
                    Expr::Ident { name, .. } => {
                        if let Some(cells) = self.arr1d.get(name) {
                            return cells.get(idx).cloned();
                        }
                        None
                    }
                    Expr::Index {
                        object: inner_obj,
                        index: row_idx,
                        ..
                    } => {
                        let row = self.fold_index(row_idx)?;
                        let col = idx;
                        let row_name = match inner_obj.as_ref() {
                            Expr::Ident { name, .. } => name,
                            _ => return None,
                        };
                        let arr = self.arr2d.get(row_name)?;
                        if (row as u32) >= arr.rows || (col as u32) >= arr.cols {
                            return None;
                        }
                        let flat = row * (arr.cols as usize) + col;
                        arr.cells.get(flat).cloned()
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn resolve_return(&self, value: &Expr) -> Option<DecomposedResult> {
        match value {
            Expr::Ident { name, .. } => {
                if let Some(arr) = self.arr2d.get(name) {
                    return Some(DecomposedResult::Array2D {
                        rows: arr.rows,
                        cols: arr.cols,
                        elements: arr.cells.clone(),
                    });
                }
                if let Some(cells) = self.arr1d.get(name) {
                    return Some(DecomposedResult::Array(cells.clone()));
                }
                if let Some(ce) = self.scalars.get(name) {
                    return Some(DecomposedResult::Scalar(ce.clone()));
                }
                None
            }
            _ => None,
        }
    }

    fn fold_index(&self, expr: &Expr) -> Option<usize> {
        let v = self.try_eval_const_scalar(expr)?;
        if v < 0 {
            return None;
        }
        Some(v as usize)
    }

    fn fold_dim_to_u32(&self, expr: &Expr) -> Option<u32> {
        let v = self.try_eval_const_scalar(expr)?;
        u32::try_from(v).ok()
    }

    fn try_eval_const_scalar(&self, expr: &Expr) -> Option<ConstInt> {
        eval_const_expr(expr, &self.const_vars)
    }
}

fn zero_field() -> ir_forge::types::FieldConst {
    ir_forge::types::FieldConst::zero()
}

fn field_from_i64(v: i64) -> ir_forge::types::FieldConst {
    // Negative constants are not expected in the shapes this module
    // handles (loop bounds and array dimensions); guard anyway with
    // a zero fallback rather than panicking.
    if v < 0 {
        return ir_forge::types::FieldConst::zero();
    }
    ir_forge::types::FieldConst::from_u64(v as u64)
}
