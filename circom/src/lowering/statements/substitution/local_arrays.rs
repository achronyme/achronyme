use super::*;

/// Lower an indexed `=` write to a registered local var array.
///
/// `prod_val[const_i] = expr` → `Let { name: "prod_val_i", value: lowered_expr }`.
/// For multi-dim, `split[i][j]` flattens via `env.strides` to a single
/// element index, then the same SSA shadow applies. Symbolic indices are
/// rejected with a structured error — circomlib's polynomial-fingerprint
/// patterns always run inside loops where `i` const-folds per iteration.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_local_array_element_assign(
    array: &str,
    indices: &[&Expr],
    value: &Expr,
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    // A multi-dim var array carries a row-major stride vector seeded at
    // declaration (`var split[k][3];` ⇒ `strides = [3]`, dropping the
    // implicit trailing 1). Its absence means the array is 1D, where
    // the only valid write is a full scalar index. With strides
    // present the dimensionality is `strides.len() + 1`.
    let dims = env.strides.get(array).map_or(1, |s| s.len() + 1);
    if indices.len() < dims {
        // Partial index: `split[i] = SplitThreeFn(...)` writes a whole
        // row. The RHS is an array; fan it out into the flat scalar
        // slots the read side resolves (`split_{base+j}`), keeping the
        // var-array model purely scalar at instantiate.
        return lower_local_array_row_assign(array, indices, value, span, sr, env, nodes, ctx);
    }

    let elem_name = resolve_local_array_element_name(array, indices, span, env, ctx)?;
    let lowered = lower_expr(value, env, ctx)?;
    nodes.push(CircuitNode::Let {
        name: elem_name,
        value: lowered,
        span: sr.clone(),
    });
    Ok(())
}

/// Lower a partial-index (row / sub-block) write into a multi-dim local
/// var array: `split[i] = SplitThreeFn(in[i], n, n, n);` with
/// `var split[k][3];`.
///
/// The RHS is an array-returning call. Circom function calls that lift
/// to Artik stage a `LetArray { name: <synth>, elements }` in
/// `ctx.pending_nodes` and return `Var(<synth>)` — the same contract the
/// whole-array `var X[R][C] = call(...)` decl-init path consumes. Here
/// the destination is one row of an already-declared flat array, so
/// instead of rebinding under a single name we write the row's
/// `row_len` cells under their flat names `{array}_{base + j}`, matching
/// the row-major linearisation the read side
/// (`linearize_multi_index`) uses for `array[i][j]`.
#[allow(clippy::too_many_arguments)]
fn lower_local_array_row_assign(
    array: &str,
    indices: &[&Expr],
    value: &Expr,
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    let strides = env.strides.get(array).cloned().ok_or_else(|| {
        LoweringError::new(
            format!(
                "partial-index write to var array `{array}` but no stride \
                 metadata is registered — only multi-dim arrays support row writes"
            ),
            span,
        )
    })?;
    let total_len = *env.arrays.get(array).ok_or_else(|| {
        LoweringError::new(
            format!("array `{array}` is not registered as a local var array"),
            span,
        )
    })?;

    // base = Σ idx_d · strides[d]; the addressed block has
    // `strides[p-1]` cells (the product of the trailing dimensions).
    let mut base: usize = 0;
    for (dim, idx_expr) in indices.iter().enumerate() {
        let fc = crate::lowering::utils::const_eval_ctx(idx_expr, ctx, env).ok_or_else(|| {
            LoweringError::new(
                format!(
                    "symbolic index in row write to var array `{array}` is not \
                     supported in circuit context — circomlib patterns assume the \
                     loop unroller resolves `i` to a constant per iteration"
                ),
                span,
            )
        })?;
        let v = fc
            .to_u64()
            .and_then(|x| usize::try_from(x).ok())
            .ok_or_else(|| {
                LoweringError::new(
                    format!("index in row write to var array `{array}` exceeds usize"),
                    span,
                )
            })?;
        let stride = strides.get(dim).copied().ok_or_else(|| {
            LoweringError::new(
                format!("stride metadata for var array `{array}` is missing dimension {dim}"),
                span,
            )
        })?;
        base += v * stride;
    }
    let row_len = strides[indices.len() - 1];

    if base + row_len > total_len {
        return Err(LoweringError::new(
            format!(
                "row write to var array `{array}` spans flat [{base}, {}) but only \
                 {total_len} elements are registered",
                base + row_len
            ),
            span,
        ));
    }

    let lowered = lower_expr(value, env, ctx)?;
    let elements = match &lowered {
        CircuitExpr::Var(source_name) => ctx.pending_nodes.iter().find_map(|node| match node {
            CircuitNode::LetArray { name, elements, .. } if name == source_name => {
                Some(elements.clone())
            }
            _ => None,
        }),
        _ => None,
    };
    let elements = elements.ok_or_else(|| {
        LoweringError::new(
            format!(
                "row write `{array}[..]` assigns a non-array value; partial-index \
                 writes into a multi-dim var array are only supported for \
                 array-returning calls (e.g. `split[i] = SplitThreeFn(...)`)"
            ),
            span,
        )
    })?;
    if elements.len() != row_len {
        return Err(LoweringError::new(
            format!(
                "row write to var array `{array}` expects {row_len} elements but \
                 the initializer produced {}",
                elements.len()
            ),
            span,
        ));
    }

    for (j, elem) in elements.into_iter().enumerate() {
        nodes.push(CircuitNode::Let {
            name: format!("{array}_{}", base + j),
            value: elem,
            span: sr.clone(),
        });
    }
    Ok(())
}

/// Resolve `array` + `indices` to a flat element name like `"prod_val_3"`.
///
/// Indices must const-fold (loop unroll bakes in the iteration index, so
/// the only callers that hit symbolic indices are misuse cases — surface
/// them as a clean lowering error). Each index is bounds-checked against
/// the registered array length; out-of-bounds writes also surface as a
/// clean error rather than silently materialising a slot that nothing
/// allocated.
pub(in crate::lowering::statements) fn resolve_local_array_element_name(
    array: &str,
    indices: &[&Expr],
    span: &diagnostics::Span,
    env: &LoweringEnv,
    ctx: &LoweringContext<'_>,
) -> Result<String, LoweringError> {
    let total_len = *env.arrays.get(array).ok_or_else(|| {
        LoweringError::new(
            format!("array `{array}` is not registered as a local var array"),
            span,
        )
    })?;

    let mut idx_values: Vec<usize> = Vec::with_capacity(indices.len());
    for idx_expr in indices {
        let fc = crate::lowering::utils::const_eval_ctx(idx_expr, ctx, env).ok_or_else(|| {
            LoweringError::new(
                format!(
                    "symbolic index in write to var array `{array}` is not supported \
                     in circuit context — circomlib patterns assume the loop unroller \
                     resolves `i` to a constant per iteration"
                ),
                span,
            )
        })?;
        let v = fc.to_u64().ok_or_else(|| {
            LoweringError::new(
                format!("index in write to var array `{array}` exceeds u64::MAX"),
                span,
            )
        })?;
        idx_values.push(v as usize);
    }

    let strides = env.strides.get(array);
    let n = idx_values.len();
    let mut linear: usize = 0;
    for (dim, &val) in idx_values.iter().enumerate() {
        let stride = if dim < n - 1 {
            strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
        } else {
            1
        };
        linear += val * stride;
    }

    if linear >= total_len {
        return Err(LoweringError::new(
            format!(
                "write to var array `{array}` at flat index {linear} is out of bounds \
                 ({total_len} elements registered)"
            ),
            span,
        ));
    }

    Ok(format!("{array}_{linear}"))
}
