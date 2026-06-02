use std::collections::{HashMap, HashSet};

use ir_forge::types::CircuitNode;

use crate::ast::{self, Expr};

use super::super::components::{inline_component_body_with_arrays, register_component_locals};
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::signals::collect_signal_names;
use super::substitution::extract_component_call;
use super::wiring::PendingComponent;

/// Lower a component declaration statement.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_component_decl<'a>(
    names: &[ast::ComponentName],
    init: Option<&Expr>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    for comp_name_decl in names {
        let comp_name = &comp_name_decl.name;

        // Component array: `component muls[n]` — register and skip init
        if !comp_name_decl.dimensions.is_empty() {
            env.component_arrays.insert(comp_name.clone());
            env.locals.insert(comp_name.clone());
            continue;
        }

        env.locals.insert(comp_name.clone());

        // If there's an initializer (`component c = Template(args)`),
        // resolve the template and prepare for signal wiring.
        if let Some(init_expr) = init {
            if let Some(call) = extract_component_call(init_expr, env, ctx)? {
                if let Some(template) = ctx.templates.get(call.template_name.as_str()) {
                    let template = *template;
                    // Register mangled output/intermediate locals
                    register_component_locals(comp_name, template, &call.scalar_args, env);

                    // Collect input signal names for wiring tracking
                    let signals = collect_signal_names(&template.body.stmts);
                    let input_signals: HashSet<String> = signals
                        .iter()
                        .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                        .map(|(n, _)| n.clone())
                        .collect();

                    if input_signals.is_empty() {
                        // No inputs to wire — inline immediately
                        let body = inline_component_body_with_arrays(
                            comp_name,
                            template,
                            &call.scalar_args,
                            &call.array_args,
                            ctx,
                            span,
                        )?;
                        nodes.extend(body);
                    } else {
                        pending.insert(
                            comp_name.clone(),
                            PendingComponent::new(
                                template,
                                call.scalar_args,
                                call.array_args,
                                input_signals,
                            ),
                        );
                    }
                } else {
                    let mut err = LoweringError::with_code(
                        format!("undefined template `{}`", call.template_name),
                        "E202",
                        span,
                    );
                    let tmpl_names: Vec<&str> = ctx.templates.keys().copied().collect();
                    if let Some(similar) = crate::lowering::suggest::find_similar(
                        &call.template_name,
                        tmpl_names.into_iter(),
                    ) {
                        err.add_suggestion(
                            diagnostics::SpanRange::from_span(span),
                            similar,
                            "a similar template exists",
                        );
                    }
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}
