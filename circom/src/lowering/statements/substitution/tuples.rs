use super::*;

/// Lower a tuple destructuring substitution.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_tuple_substitution<'a>(
    targets: &[Expr],
    op: AssignOp,
    value: &Expr,
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // RHS must be a tuple with same arity, or an anonymous component
    if let Expr::Tuple {
        elements: values, ..
    } = value
    {
        if values.len() != targets.len() {
            return Err(LoweringError::new(
                format!(
                    "tuple length mismatch: {} targets but {} values",
                    targets.len(),
                    values.len()
                ),
                span,
            ));
        }
        for (t, v) in targets.iter().zip(values.iter()) {
            // Skip underscore targets
            if matches!(t, Expr::Underscore { .. }) {
                continue;
            }
            lower_substitution(t, op, v, span, env, nodes, ctx, pending)?;
        }
        return Ok(());
    }

    // RHS is an anonymous component — inline it, then wire its outputs
    // to the tuple targets in declaration order.
    if let Expr::AnonComponent {
        callee,
        template_args,
        signal_args,
        ..
    } = value
    {
        return lower_anon_component_tuple(
            targets,
            op,
            callee,
            template_args,
            signal_args,
            span,
            sr,
            env,
            nodes,
            ctx,
        );
    }

    Err(LoweringError::new(
        "tuple destructuring requires a tuple or anonymous component on the right side",
        span,
    ))
}

/// Lower an anonymous component call with tuple output.
#[allow(clippy::too_many_arguments)]
fn lower_anon_component_tuple(
    targets: &[Expr],
    op: AssignOp,
    callee: &Expr,
    template_args: &[Expr],
    signal_args: &[AnonSignalArg],
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    let tmpl_name = match callee {
        Expr::Ident { name, .. } => name.clone(),
        _ => {
            return Err(LoweringError::new(
                "anonymous component callee must be an identifier",
                span,
            ))
        }
    };
    let template = *ctx.templates.get(tmpl_name.as_str()).ok_or_else(|| {
        let mut err =
            LoweringError::with_code(format!("template `{tmpl_name}` not found"), "E202", span);
        let tmpl_names: Vec<&str> = ctx.templates.keys().copied().collect();
        if let Some(similar) =
            crate::lowering::suggest::find_similar(&tmpl_name, tmpl_names.into_iter())
        {
            err.add_suggestion(
                diagnostics::SpanRange::from_span(span),
                similar,
                "a similar template exists",
            );
        }
        err
    })?;

    // Lower template arguments
    let lowered_args: Vec<CircuitExpr> = template_args
        .iter()
        .map(|a| lower_expr(a, env, ctx))
        .collect::<Result<_, _>>()?;

    // Generate a unique internal name for the anonymous component
    let anon_name = format!("_anon_{}", ctx.next_anon_id());

    // Register component locals (output/intermediate signals)
    register_component_locals(&anon_name, template, &lowered_args, env);

    // Collect output signal names in declaration order
    let signals = collect_signal_names(&template.body.stmts);
    let output_names: Vec<String> = signals
        .iter()
        .filter(|(_, st)| matches!(st, ast::SignalType::Output))
        .map(|(n, _)| n.clone())
        .collect();

    let input_names: Vec<String> = signals
        .iter()
        .filter(|(_, st)| matches!(st, ast::SignalType::Input))
        .map(|(n, _)| n.clone())
        .collect();

    // Wire input signals from signal_args
    for (i, arg) in signal_args.iter().enumerate() {
        let sig_name: String = if let Some(name) = &arg.name {
            name.clone()
        } else if i < input_names.len() {
            input_names[i].clone()
        } else {
            return Err(LoweringError::new(
                "too many signal arguments for anonymous component",
                span,
            ));
        };
        let wired_name = format!("{anon_name}.{sig_name}");
        let lowered_val = lower_expr(&arg.value, env, ctx)?;
        nodes.push(CircuitNode::Let {
            name: wired_name,
            value: lowered_val,
            span: sr.clone(),
        });
    }

    // Inline the component body
    let body = inline_component_body(&anon_name, template, &lowered_args, ctx, span)?;
    nodes.extend(body);

    // Wire output signals to tuple targets
    if targets.len() > output_names.len() {
        return Err(LoweringError::new(
            format!(
                "tuple has {} targets but template `{tmpl_name}` has {} outputs",
                targets.len(),
                output_names.len()
            ),
            span,
        ));
    }
    for (t, out_name) in targets.iter().zip(output_names.iter()) {
        if matches!(t, Expr::Underscore { .. }) {
            continue;
        }
        let target_name = match t {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(LoweringError::new(
                    "tuple target must be an identifier or underscore",
                    span,
                ))
            }
        };
        let comp_output = CircuitExpr::Var(format!("{anon_name}.{out_name}"));
        match op {
            AssignOp::ConstraintAssign => {
                nodes.push(CircuitNode::Let {
                    name: target_name.clone(),
                    value: comp_output.clone(),
                    span: sr.clone(),
                });
                nodes.push(CircuitNode::AssertEq {
                    lhs: CircuitExpr::Var(target_name),
                    rhs: comp_output,
                    message: None,
                    span: sr.clone(),
                });
            }
            AssignOp::SignalAssign => {
                nodes.push(CircuitNode::WitnessHint {
                    name: target_name,
                    hint: comp_output,
                    span: sr.clone(),
                });
            }
            AssignOp::Assign => {
                nodes.push(CircuitNode::Let {
                    name: target_name,
                    value: comp_output,
                    span: sr.clone(),
                });
            }
            _ => unreachable!("reverse operators desugared before tuple handling"),
        }
    }
    Ok(())
}
