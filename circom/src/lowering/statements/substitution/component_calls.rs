use super::*;

/// Parsed component call with scalar and array template arguments.
pub(in crate::lowering::statements) struct ComponentCall {
    pub template_name: String,
    pub scalar_args: Vec<CircuitExpr>,
    pub array_args: HashMap<String, EvalValue>,
}

/// Extract a template call from a component initializer expression.
///
/// `Template(arg1, arg2)` → `Some(ComponentCall { ... })`
///
/// Arguments that refer to known compile-time arrays (from `env.known_array_values`)
/// are stored in `array_args` instead of being lowered to `CircuitExpr`.
pub(in crate::lowering::statements) fn extract_component_call(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<Option<ComponentCall>, LoweringError> {
    if let Expr::Call { callee, args, span } = expr {
        if let Some(name) = extract_ident_name(callee) {
            // Check if this is a bus type being used as a component
            if ctx.bus_names.contains(name.as_str()) {
                return Err(LoweringError::with_code(
                    format!(
                        "`{name}` is a bus type, not a template; bus types require \
                         Circom ≥2.2.0 bus compilation support which is not yet implemented"
                    ),
                    "E205",
                    span,
                ));
            }

            // Collect array arg indices before lowering (avoids borrow conflicts)
            let mut array_arg_indices: Vec<(usize, String, EvalValue)> = Vec::new();
            for (i, arg) in args.iter().enumerate() {
                if let Some(arg_name) = extract_ident_name(arg) {
                    if let Some(arr_val) = env.known_array_values.get(&arg_name) {
                        array_arg_indices.push((i, arg_name, arr_val.clone()));
                        continue;
                    }
                }
                // Partially-indexed array (e.g. `PBASE[i]` where `PBASE`
                // is 2D). Resolve the leading compile-time indices and
                // check whether the remaining shape is still an array
                // — in which case pass it as an array arg to the
                // callee rather than coercing it through scalar lowering.
                if let Some(slice) = resolve_partial_array_slice(arg, env, ctx) {
                    if matches!(slice, EvalValue::Array(_)) {
                        array_arg_indices.push((i, format!("__slice_{i}"), slice));
                        continue;
                    }
                }
                // Inline array literal at the call site, e.g.
                // `EscalarMul(8, [Gx, Gy])`. Pass it as an array arg
                // so the callee's body sees the param in
                // `known_array_values` rather than scalar-coercing the
                // first element. Only fold when every element is a
                // compile-time field constant.
                if let Expr::ArrayLit { elements, .. } = arg {
                    let folded: Option<Vec<EvalValue>> = elements
                        .iter()
                        .map(|e| {
                            crate::lowering::utils::const_eval_ctx(e, ctx, env)
                                .map(|fc| EvalValue::Scalar(BigVal::from_field_const(fc)))
                        })
                        .collect();
                    if let Some(vals) = folded {
                        array_arg_indices.push((i, format!("__lit_{i}"), EvalValue::Array(vals)));
                    }
                }
            }

            let mut lowered_args = Vec::new();
            let array_indices: HashSet<usize> =
                array_arg_indices.iter().map(|(i, _, _)| *i).collect();
            for (i, arg) in args.iter().enumerate() {
                if array_indices.contains(&i) {
                    lowered_args.push(CircuitExpr::Const(FieldConst::zero()));
                } else {
                    let lowered = lower_expr(arg, env, ctx)?;
                    // Resolve Var/Capture to Const when the value is known.
                    // This is critical for pending components created inside
                    // loops: if we store Var("nseg"), the flush at a later
                    // iteration would pick up the wrong value.
                    //
                    // 3-source O(1) lookup, NOT the merged `all_constants`
                    // map: this path has no fallback (a miss keeps
                    // `Var(name)`, which propagates into emitted
                    // constraints), so it must consult `bound_const_vars`
                    // too — `resolve_constant_with_bound` reproduces the
                    // exact `all_constants` first-wins precedence without
                    // rebuilding the map on every component-call extraction
                    // inside the unrolled ladder.
                    let resolved = match &lowered {
                        CircuitExpr::Var(name) | CircuitExpr::Capture(name) => {
                            if let Some(val) = ctx.resolve_constant_with_bound(name, env) {
                                CircuitExpr::Const(val)
                            } else {
                                lowered
                            }
                        }
                        _ => lowered,
                    };
                    lowered_args.push(resolved);
                }
            }

            // Map template param names → array values
            let mut array_args = HashMap::new();
            if let Some(template) = ctx.templates.get(name.as_str()) {
                for (i, _arg_name, arr_val) in &array_arg_indices {
                    if let Some(param_name) = template.params.get(*i) {
                        array_args.insert(param_name.clone(), arr_val.clone());
                    }
                }
            }
            return Ok(Some(ComponentCall {
                template_name: name,
                scalar_args: lowered_args,
                array_args,
            }));
        }
        return Err(LoweringError::new(
            "component template call must use a simple name",
            span,
        ));
    }
    Ok(None)
}

/// Resolve an expression like `PBASE[i]` (or `M[i][j]` partial, etc.)
/// to a sub-slice of a registered known-array value.
///
/// Walks the chain of `Expr::Index` back to the base `Ident`, folds
/// each index to a compile-time `usize` using `ctx.all_constants(env)`,
/// and steps through the nested `EvalValue::Array` stored in
/// `env.known_array_values`. Returns the resulting `EvalValue` —
/// scalar if fully indexed, sub-array if only the leading dimensions
/// were resolved (e.g. `PBASE[3]` over a 10x2 → 2-element Array).
///
/// Returns `None` if the base isn't a known array, any index fails
/// to fold, or an index is out of bounds.
fn resolve_partial_array_slice(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<EvalValue> {
    let mut indices: Vec<&Expr> = Vec::new();
    let mut cursor = expr;
    while let Expr::Index { object, index, .. } = cursor {
        indices.push(index);
        cursor = object;
    }
    let base_name = if let Expr::Ident { name, .. } = cursor {
        name.as_str()
    } else {
        return None;
    };
    let mut slice = env.known_array_values.get(base_name)?.clone();
    // indices collected outermost-to-innermost traversal is reversed
    indices.reverse();

    for idx_expr in &indices {
        let idx_fc = crate::lowering::utils::const_eval_ctx(idx_expr, ctx, env)?;
        let idx = idx_fc.to_u64()? as usize;
        let next = match &slice {
            EvalValue::Array(elems) => elems.get(idx)?.clone(),
            _ => return None,
        };
        slice = next;
    }
    Some(slice)
}
