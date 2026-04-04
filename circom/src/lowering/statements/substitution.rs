//! Substitution lowering: signal assignments, component wiring, tuple destructuring.
//!
//! Handles all forms of `target op value` statements:
//! - `<==` (constraint assign) → Let + AssertEq
//! - `<--` (signal assign) → WitnessHint
//! - `=` (variable assign) → Let (SSA shadowing)
//! - `==>`, `-->` (reverse operators) → desugared to `<==`, `<--`
//! - Tuple destructuring and anonymous component multi-output

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst};

use crate::ast::{self, AnonSignalArg, AssignOp, CompoundOp, Expr};

use super::super::components::{
    inline_component_body, inline_component_body_with_arrays, register_component_locals,
};
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::signals::collect_signal_names;
use super::super::utils::{extract_ident_name, EvalValue};
use super::targets::{
    extract_assign_target_with_constants, extract_target_name, linearize_multi_index,
    try_resolve_component_array_target, AssignTarget,
};
use super::wiring::{maybe_trigger_inline, PendingComponent};

/// Lower a substitution statement (`target op value`).
///
/// Handles both simple identifiers and dot access targets (component
/// signal wirings like `c.a <== expr`).
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_substitution<'a>(
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Build combined constants map (known_constants + param_values) for target resolution
    let all_constants = ctx.all_constants(env);

    // Desugar reverse operators: `expr ==> target` → `target <== expr`
    //                            `expr --> target` → `target <-- expr`
    let (target, op, value) = match op {
        AssignOp::RConstraintAssign => (value, AssignOp::ConstraintAssign, target),
        AssignOp::RSignalAssign => (value, AssignOp::SignalAssign, target),
        other => (target, other, value),
    };

    let sr = Some(SpanRange::from_span(span));

    // ── Tuple destructuring ────────────────────────────────────────
    if let Expr::Tuple {
        elements: targets, ..
    } = target
    {
        return lower_tuple_substitution(targets, op, value, span, &sr, env, nodes, ctx, pending);
    }

    match op {
        // `target <== expr` → Let + AssertEq (or LetIndexed + AssertEq for arrays)
        AssignOp::ConstraintAssign => {
            let assign_target = extract_assign_target_with_constants(target, &all_constants)
                .ok_or_else(|| {
                    LoweringError::new(
                        "constraint assignment target must be an identifier, \
                     component signal, or array element",
                        span,
                    )
                })?;
            let lowered = lower_expr(value, env, ctx)?;
            match assign_target {
                AssignTarget::Scalar(name) => {
                    nodes.push(CircuitNode::Let {
                        name: name.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::Var(name),
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    nodes.push(CircuitNode::LetIndexed {
                        array: array.clone(),
                        index: idx_expr.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::ArrayIndex {
                            array,
                            index: Box::new(idx_expr),
                        },
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::LetIndexed {
                        array: array.clone(),
                        index: idx_expr.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::ArrayIndex {
                            array,
                            index: Box::new(idx_expr),
                        },
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env)?;
        }

        // `target <-- expr` → WitnessHint or WitnessHintIndexed
        AssignOp::SignalAssign => {
            let assign_target = extract_assign_target_with_constants(target, &all_constants)
                .ok_or_else(|| {
                    LoweringError::new(
                        "signal assignment target must be an identifier, \
                     component signal, or array element",
                        span,
                    )
                })?;
            let lowered = lower_expr(value, env, ctx)?;
            match assign_target {
                AssignTarget::Scalar(name) => {
                    nodes.push(CircuitNode::WitnessHint {
                        name,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env)?;
        }

        // RConstraintAssign (==>) and RSignalAssign (-->) are desugared
        // to ConstraintAssign (<==) and SignalAssign (<--) above.
        AssignOp::RConstraintAssign | AssignOp::RSignalAssign => {
            unreachable!("reverse operators desugared at function entry")
        }

        // `target = expr` → variable reassignment, component array instantiation, or SSA shadowing
        AssignOp::Assign => {
            lower_var_assign(target, value, span, &sr, &all_constants, env, nodes, ctx, pending)?;
        }
    }

    Ok(())
}

/// Lower a variable assignment (`target = value`).
#[allow(clippy::too_many_arguments)]
fn lower_var_assign<'a>(
    target: &Expr,
    value: &Expr,
    span: &diagnostics::Span,
    sr: &Option<SpanRange>,
    _all_constants: &HashMap<String, u64>,
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
                        PendingComponent {
                            template,
                            template_args: call.scalar_args,
                            array_args: call.array_args,
                            input_signals,
                            wired_signals: HashSet::new(),
                            has_indexed_wirings: false,
                        },
                    );
                }
            }
        }
        return Ok(());
    }

    let name = extract_target_name(target).ok_or_else(|| {
        LoweringError::new(
            "assignment target must be an identifier in circuit context",
            span,
        )
    })?;
    let lowered = lower_expr(value, env, ctx)?;
    nodes.push(CircuitNode::Let {
        name,
        value: lowered,
        span: sr.clone(),
    });

    Ok(())
}

/// Lower a tuple destructuring substitution.
#[allow(clippy::too_many_arguments)]
fn lower_tuple_substitution<'a>(
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
        let mut err = LoweringError::with_code(
            format!("template `{tmpl_name}` not found"),
            "E202",
            span,
        );
        let tmpl_names: Vec<&str> = ctx.templates.keys().copied().collect();
        if let Some(similar) = crate::lowering::suggest::find_similar(&tmpl_name, tmpl_names.into_iter()) {
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

/// Parsed component call with scalar and array template arguments.
pub(super) struct ComponentCall {
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
pub(super) fn extract_component_call(
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
                    lowered_args.push(lower_expr(arg, env, ctx)?);
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

/// Convert a compound assignment operator to a CircuitExpr binary op.
pub(super) fn compound_to_binop(
    op: CompoundOp,
    lhs: &CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let l = Box::new(lhs.clone());
    let r = Box::new(rhs);

    match op {
        CompoundOp::Add => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Sub => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Mul => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Div => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        CompoundOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        CompoundOp::Pow => {
            let exp = match r.as_ref() {
                CircuitExpr::Const(fc) => fc.to_u64().ok_or_else(|| {
                    LoweringError::new("power exponent must be a small constant", span)
                })?,
                _ => {
                    return Err(LoweringError::new(
                        "power exponent must be a compile-time constant",
                        span,
                    ));
                }
            };
            Ok(CircuitExpr::Pow { base: l, exp })
        }
        CompoundOp::ShiftL
        | CompoundOp::ShiftR
        | CompoundOp::BitAnd
        | CompoundOp::BitOr
        | CompoundOp::BitXor => Err(LoweringError::new(
            "bitwise compound assignment is not supported in circuit context",
            span,
        )),
    }
}
