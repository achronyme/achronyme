use diagnostics::SpanRange;
use ir_forge::types::{CircuitExpr, CircuitNode};

use crate::ast::Expr;

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::arrays::{expand_eval_value_to_nodes, try_eval_array_init};

/// Lower a variable declaration statement.
pub(super) fn lower_var_decl(
    names: &[String],
    dimensions: &[Expr],
    init: Option<&Expr>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    // `var X[N1][N2]...;` (no init): allocate zero-initialized
    // per-element Lets when all dimensions are compile-time constants.
    // The polynomial-fingerprint pattern in circomlib's BigMultNoCarry /
    // BigMultShortLong needs this so subsequent `X[i] = expr` writes have
    // a backing slot to land in via the SSA shadow path.
    if init.is_none() && !dimensions.is_empty() {
        return lower_uninit_array_var_decl(names, dimensions, span, env, nodes, ctx);
    }

    if let Some(value) = init {
        if names.len() == 1 {
            // Skip nested (2D+) array literals already resolved by precompute_all
            // (e.g., `var BASE[10][2] = [[...], ...]` in Pedersen). These can't be
            // lowered via lower_expr (ArrayLit unsupported), but their values resolve
            // from known_array_values at compile time. Flat 1D array literals are
            // expanded to Let nodes below for use in circuit expressions.
            if env.known_array_values.contains_key(&names[0]) {
                if let Expr::ArrayLit { elements, .. } = value {
                    if elements.iter().any(|e| matches!(e, Expr::ArrayLit { .. })) {
                        return Ok(());
                    }
                }
            }

            // Check for array literal: `var arr = [1, 2, 3]`
            if let Expr::ArrayLit { elements, .. } = value {
                let base = &names[0];
                for (i, elem) in elements.iter().enumerate() {
                    let elem_name = format!("{base}_{i}");
                    let lowered = lower_expr(elem, env, ctx)?;
                    nodes.push(CircuitNode::Let {
                        name: elem_name.clone(),
                        value: lowered,
                        span: Some(SpanRange::from_span(span)),
                    });
                    env.locals.insert(elem_name);
                }
                env.register_array(names[0].clone(), elements.len());
                // NB: array-literal `var X = [1,2,3];` inits are NOT
                // registered in `env.local_var_arrays`. Reads of `X[i]`
                // already resolve at lowering time via the constant
                // expansion above (each slot becomes a const-valued
                // `Let`), and the loop classifier's read-side preempt
                // is only required for the uninit-then-shadowed-write
                // case (`var X[N]; X[i] = expr;`) where slot values
                // can be CircuitExprs that the const-fold path cannot
                // collapse. A future template that writes through
                // `X[i] +=` after such a literal init would need a
                // separate gate — none in the current circomlib corpus.
            } else if let Some(eval_val) = try_eval_array_init(value, env, ctx) {
                // Function call or expression that evaluates to an array
                // at compile time (e.g. `var C[n] = POSEIDON_C(t)`).
                let base = &names[0];
                expand_eval_value_to_nodes(
                    base,
                    &eval_val,
                    nodes,
                    env,
                    &Some(SpanRange::from_span(span)),
                );
                env.known_array_values.insert(base.clone(), eval_val);
            } else {
                // Try compile-time evaluation for var inits that are pure
                // constant expressions. This is critical for patterns like
                // `var b = (1 << 128) - 1` in CompConstant — without this,
                // the expression becomes a circuit-level ShiftL that fails
                // range checks during R1CS compilation.
                //
                // When the eval succeeds, also seed `env.bound_const_vars`
                // with the resolved value so a subsequent loop bound or
                // component-array sizing expression that references this
                // var (e.g. `var n1 = n\2; for (i = 0; i < n1; i++)` in
                // gates.circom MultiAND) can resolve through `all_constants`.
                // The dedicated field — distinct from `known_constants` —
                // avoids folding subsequent mutations of the same name
                // (e.g. `var lc1 = 0; lc1 += ...` in Num2Bits) into a
                // stale literal.
                let lowered =
                    if let Some(fc) = crate::lowering::utils::const_eval_ctx(value, ctx, env) {
                        env.bound_const_vars.insert(names[0].clone(), fc);
                        CircuitExpr::Const(fc)
                    } else {
                        lower_expr(value, env, ctx)?
                    };

                // Array-valued function-call init: when the lift (Artik)
                // returns `LiftedShape::Array`, the call site stages a
                // `LetArray { name: <synth>, elements }` in
                // `ctx.pending_nodes` and returns `Var(<synth>)`. A naive
                // scalar `Let { name: outCalc, value: Var(<synth>) }`
                // would make `outCalc` an alias of the synth *array*
                // binding — which trips a scalar/array type mismatch at
                // instantiate time when the caller reads `outCalc[i]`.
                // Rebind under the destination name as a LetArray so
                // subsequent indexed reads resolve element-wise.
                if let CircuitExpr::Var(source_name) = &lowered {
                    let matching = ctx.pending_nodes.iter().find_map(|node| match node {
                        CircuitNode::LetArray { name, elements, .. } if name == source_name => {
                            Some(elements.clone())
                        }
                        _ => None,
                    });
                    if let Some(elements) = matching {
                        let len = elements.len();
                        // Multi-dim destination (`var X[R][C] = call(...)`):
                        // the Artik lift flattens 2D returns to a 1D
                        // `LetArray` with `rows*cols` slots, losing the
                        // declared shape. Seed `env.strides` from the
                        // syntactic dimensions so subsequent `X[i][j]`
                        // reads linearise via `linearize_multi_index`
                        // (i * cols + j) instead of falling back to
                        // stride=1 or surfacing E213 when the outer
                        // index lands on a memoization placeholder.
                        if dimensions.len() > 1 {
                            let dim_values = resolve_const_dimensions(dimensions, span, env, ctx)?;
                            let declared_total: usize = dim_values.iter().product();
                            if declared_total != len {
                                return Err(LoweringError::new(
                                    format!(
                                        "declared shape of `{}` has {} cells \
                                         (dimensions {:?}) but the initializer \
                                         produced {} elements",
                                        names[0], declared_total, dim_values, len
                                    ),
                                    span,
                                ));
                            }
                            let strides = compute_row_major_strides(&dim_values);
                            if !strides.is_empty() {
                                env.strides.insert(names[0].clone(), strides);
                            }
                        }
                        nodes.push(CircuitNode::LetArray {
                            name: names[0].clone(),
                            elements,
                            span: Some(SpanRange::from_span(span)),
                        });
                        env.register_array(names[0].clone(), len);
                        env.locals.insert(names[0].clone());
                        return Ok(());
                    }
                }

                nodes.push(CircuitNode::Let {
                    name: names[0].clone(),
                    value: lowered,
                    span: Some(SpanRange::from_span(span)),
                });
                env.locals.insert(names[0].clone());
            }
        } else {
            // Tuple var decl: `var (a, b) = (expr1, expr2)` — element-wise
            if let Expr::Tuple { elements, .. } = value {
                if elements.len() != names.len() {
                    return Err(LoweringError::new(
                        format!(
                            "tuple length mismatch: {} names but {} values",
                            names.len(),
                            elements.len()
                        ),
                        span,
                    ));
                }
                for (name, elem) in names.iter().zip(elements.iter()) {
                    let lowered = lower_expr(elem, env, ctx)?;
                    nodes.push(CircuitNode::Let {
                        name: name.clone(),
                        value: lowered,
                        span: Some(SpanRange::from_span(span)),
                    });
                    env.locals.insert(name.clone());
                }
            } else {
                return Err(LoweringError::new(
                    "tuple variable declaration requires a tuple on the right side",
                    span,
                ));
            }
        }
    } else {
        // Uninitialized scalar var — just register name, will be assigned later.
        for name in names {
            env.locals.insert(name.clone());
        }
    }
    Ok(())
}

/// Allocate per-element zero-initialized slots for an uninitialized
/// array var declaration (`var X[N];`, `var X[N][M];`).
///
/// Each leaf slot becomes a `CircuitNode::Let { name: "X_i_..._j", value: Const(0) }`,
/// registered as an array of `total_len` elements with row-major
/// strides. Subsequent indexed writes (`X[i] = expr`, `X[i] += expr`)
/// re-bind these slots under the same flat element name via SSA shadow,
/// and indexed reads resolve through `env.resolve_array_element` →
/// `CircuitExpr::Var("X_i")` exactly like signal-array reads.
///
/// Errors:
/// - any dimension that is not compile-time-foldable
/// - any dimension that exceeds `u32::MAX` (defensive — `Vec` capacity)
/// - a name already registered as an array, input, or capture
fn lower_uninit_array_var_decl(
    names: &[String],
    dimensions: &[Expr],
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    let dim_values = resolve_const_dimensions(dimensions, span, env, ctx)?;
    let total_len: usize = dim_values.iter().product();
    let strides = compute_row_major_strides(&dim_values);
    let sr = Some(SpanRange::from_span(span));

    for base in names {
        // Shadow check: reject collisions against any existing binding
        // that already owns the same flat slot namespace
        // (`<base>_<i>`). Signals (inputs / locals / captures) and
        // pre-existing array registrations all qualify — a silent
        // shadow would let the zero-init `Let`s mask real signal
        // bindings and produce wrong constraints.
        if env.inputs.contains(base)
            || env.captures.contains(base)
            || env.locals.contains(base)
            || env.arrays.contains_key(base)
        {
            return Err(LoweringError::new(
                format!(
                    "var `{base}` shadows an existing signal, capture, or array of the same name"
                ),
                span,
            ));
        }
        for i in 0..total_len {
            let elem_name = format!("{base}_{i}");
            nodes.push(CircuitNode::Let {
                name: elem_name.clone(),
                value: CircuitExpr::Const(ir_forge::types::FieldConst::from_u64(0)),
                span: sr.clone(),
            });
            env.locals.insert(elem_name);
        }
        env.register_array(base.clone(), total_len);
        env.local_var_arrays.insert(base.clone());
        if !strides.is_empty() {
            env.strides.insert(base.clone(), strides.clone());
        }
        env.locals.insert(base.clone());
    }

    Ok(())
}

/// Resolve a sequence of array-dimension expressions to `usize` values.
///
/// Each dimension must const-fold against `ctx + env`. Errors loudly on
/// non-const dimensions and on values that exceed `u32::MAX` (defensive
/// — `Vec` capacity).
fn resolve_const_dimensions(
    dimensions: &[Expr],
    span: &diagnostics::Span,
    env: &LoweringEnv,
    ctx: &LoweringContext<'_>,
) -> Result<Vec<usize>, LoweringError> {
    let mut dim_values: Vec<usize> = Vec::with_capacity(dimensions.len());
    for d in dimensions {
        let fc = crate::lowering::utils::const_eval_ctx(d, ctx, env).ok_or_else(|| {
            LoweringError::new(
                "var array dimension must be a compile-time constant in circuit context",
                span,
            )
        })?;
        let v = fc.to_u64().ok_or_else(|| {
            LoweringError::new(
                "var array dimension exceeds u64::MAX in circuit context",
                span,
            )
        })?;
        if v > u32::MAX as u64 {
            return Err(LoweringError::new(
                "var array dimension exceeds u32::MAX in circuit context",
                span,
            ));
        }
        dim_values.push(v as usize);
    }
    Ok(dim_values)
}

/// Row-major strides for a multi-dimensional array shape.
///
/// `[a, b, c]` → strides `[b*c, c]` (the trailing stride is implicit
/// 1 — `lower_multi_index` already treats the last dim that way).
/// `[a]` → empty vec.
fn compute_row_major_strides(dims: &[usize]) -> Vec<usize> {
    if dims.len() <= 1 {
        return Vec::new();
    }
    let mut strides = Vec::with_capacity(dims.len() - 1);
    for i in 0..dims.len() - 1 {
        strides.push(dims[i + 1..].iter().product());
    }
    strides
}
