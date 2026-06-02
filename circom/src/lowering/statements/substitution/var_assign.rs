use super::local_arrays::lower_local_array_element_assign;
use super::*;

/// Lower a variable assignment (`target = value`).
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_var_assign<'a>(
    target: &Expr,
    value: &Expr,
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Tag value assignment: signal.tag = expr
    // In Circom, tags are metadata that don't produce circuit nodes.
    if let Expr::DotAccess { object, field, .. } = target {
        if let Some(obj_name) = extract_ident_name(object) {
            let mangled = format!("{obj_name}.{field}");
            let is_component_signal = env.locals.contains(&mangled)
                || env.inputs.contains(&mangled)
                || pending.contains_key(&obj_name);
            if !is_component_signal
                && (env.inputs.contains(&obj_name) || env.locals.contains(&obj_name))
            {
                // This is a signal tag assignment — no circuit semantics.
                return Ok(());
            }
        }
    }

    // Component array element instantiation: muls[i] = Template()
    // Also handles 2D: sigmaF[r][j] = Sigma()
    if let Some(comp_name) = try_resolve_component_array_target(target, env, ctx) {
        env.locals.insert(comp_name.clone());

        if let Some(call) = extract_component_call(value, env, ctx)? {
            if let Some(template) = ctx.templates.get(call.template_name.as_str()) {
                let template = *template;
                register_component_locals(&comp_name, template, &call.scalar_args, env);

                let signals = collect_signal_names(&template.body.stmts);
                let input_signals: HashSet<String> = signals
                    .iter()
                    .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                    .map(|(n, _)| n.clone())
                    .collect();

                if input_signals.is_empty() {
                    let body = inline_component_body_with_arrays(
                        &comp_name,
                        template,
                        &call.scalar_args,
                        &call.array_args,
                        ctx,
                        span,
                    )?;
                    nodes.extend(body);
                } else {
                    pending.insert(
                        comp_name,
                        PendingComponent::new(
                            template,
                            call.scalar_args,
                            call.array_args,
                            input_signals,
                        ),
                    );
                }
            }
        }
        return Ok(());
    }

    // Indexed `=` write to a template-local var array (e.g.
    // `prod_val[i] = 0;` in BigMultNoCarry's polynomial-fingerprint
    // pattern). Re-bind the element's SSA slot under its flat name
    // (`prod_val_3`) via Let-shadow; subsequent reads of `prod_val[3]`
    // resolve to `Var(prod_val_3)` through `env.resolve_array_element`.
    //
    // **Discrimination from signal arrays:** signal arrays use `<==`
    // (`AssignOp::ConstraintAssign`) and `<--` (`AssignOp::SignalAssign`);
    // the `AssignOp::Assign` arm above is uniquely entered for var
    // statements. Do not widen this branch to the constraint / witness
    // ops — those have their own `LetIndexed` / `WitnessHintIndexed`
    // paths above that emit IR shapes the instantiate pass understands
    // (signal arrays carry a `WitnessArrayDecl` shape; var arrays do
    // not). A widened path would emit an SSA-shadow `Let` on a signal
    // wire name and silently underconstraint the signal.
    if let Some(assign_target) = extract_assign_target_ctx(target, ctx, env) {
        match assign_target {
            AssignTarget::Indexed { array, index } => {
                if env.arrays.contains_key(&array) {
                    let idx_refs: [&Expr; 1] = [index.as_ref()];
                    return lower_local_array_element_assign(
                        &array, &idx_refs, value, span, sr, env, nodes, ctx,
                    );
                }
            }
            AssignTarget::MultiIndexed { array, indices } => {
                if env.arrays.contains_key(&array) {
                    let idx_refs: Vec<&Expr> = indices.iter().collect();
                    return lower_local_array_element_assign(
                        &array, &idx_refs, value, span, sr, env, nodes, ctx,
                    );
                }
            }
            AssignTarget::Scalar(_) => {
                // Falls through to the Ident-only path below.
            }
        }
    }

    let name = extract_target_name(target).ok_or_else(|| {
        LoweringError::new(
            "assignment target must be an identifier in circuit context",
            span,
        )
    })?;

    // Array-valued reassignment (e.g. `table = EscalarMulW4Table(base, k);`
    // inside `EscalarMulWindow` after a prior `var table[16][2];`
    // declaration). Try compile-time evaluation; if the function returns
    // an array, expand to per-element Let bindings and register the
    // result under the target name so subsequent `table[i][j]` reads
    // resolve via `env.known_array_values`.
    if let Some(eval_val) = super::super::arrays::try_eval_array_init(value, env, ctx) {
        super::super::arrays::expand_eval_value_to_nodes(&name, &eval_val, nodes, env, sr);
        env.known_array_values.insert(name.clone(), eval_val);
        env.locals.insert(name);
        return Ok(());
    }

    // Deferred scalar component instantiation: `component c; ...; c = T();`
    // circomlib uses this idiom (e.g. `component mux = MultiMux4(2);`
    // split into `component mux;` followed by `mux = MultiMux4(2);`
    // inside `EscalarMulWindow`). Detect by checking whether the RHS
    // is a call to a registered template; if so, route through the
    // same machinery as `component c = T()`.
    if let Expr::Call { callee, .. } = value {
        if let Some(fn_name) = extract_ident_name(callee) {
            if ctx.templates.contains_key(fn_name.as_str()) {
                if let Some(call) = extract_component_call(value, env, ctx)? {
                    if let Some(template) = ctx.templates.get(call.template_name.as_str()) {
                        let template = *template;
                        register_component_locals(&name, template, &call.scalar_args, env);
                        let signals = collect_signal_names(&template.body.stmts);
                        let input_signals: HashSet<String> = signals
                            .iter()
                            .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                            .map(|(n, _)| n.clone())
                            .collect();
                        if input_signals.is_empty() {
                            let body = inline_component_body_with_arrays(
                                &name,
                                template,
                                &call.scalar_args,
                                &call.array_args,
                                ctx,
                                span,
                            )?;
                            nodes.extend(body);
                        } else {
                            pending.insert(
                                name.clone(),
                                PendingComponent::new(
                                    template,
                                    call.scalar_args,
                                    call.array_args,
                                    input_signals,
                                ),
                            );
                        }
                        env.locals.insert(name);
                        return Ok(());
                    }
                }
            }
        }
    }

    // Track compile-time var assignments so loop bounds and array indices
    // can reference them (e.g., `var nseg = (s < n-1) ? 249 : last;`).
    // Use param_values (not known_constants) to avoid affecting Ident
    // resolution in lower_expr — vars like `lc1` may be modified later.
    if let Some(val) = crate::lowering::utils::const_eval_ctx(value, ctx, env) {
        ctx.param_values.insert(name.clone(), val);
    }

    let lowered = lower_expr(value, env, ctx)?;
    nodes.push(CircuitNode::Let {
        name,
        value: lowered,
        span: sr.clone(),
    });

    Ok(())
}
