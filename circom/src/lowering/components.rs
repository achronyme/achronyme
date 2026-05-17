//! Component instantiation: inline Circom template bodies.
//!
//! When a Circom template instantiates a component:
//! ```circom
//! component c = Multiplier();
//! c.a <== x;
//! c.b <== y;
//! out <== c.out;
//! ```
//!
//! We inline the template body at the point where all input signals are wired,
//! mangling signal/variable names with the component prefix (`c_a`, `c_b`, `c_c`).
//!
//! The mangling format matches the existing `DotAccess` lowering in `expressions.rs`:
//! `component_field` (single underscore separator).

use std::collections::{HashMap, HashSet};

use ir_forge::types::mangle::mangle_nodes;
use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst};

use crate::ast::TemplateDef;

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::signals::{collect_signal_names, extract_signal_array_sizes, extract_signal_strides};
use super::statements::lower_stmts;
use super::utils::EvalValue;

/// Inline a component's template body with mangled names.
///
/// Returns a list of `CircuitNode`s from the template body, with all
/// variable names prefixed by `comp_name_` and template parameter
/// captures substituted with argument expressions.
///
/// The caller is responsible for emitting the signal wirings (Let bindings)
/// before these nodes.
pub fn inline_component_body<'a>(
    comp_name: &str,
    template: &'a TemplateDef,
    template_args: &[CircuitExpr],
    ctx: &mut LoweringContext<'a>,
    span: &diagnostics::Span,
) -> Result<Vec<CircuitNode>, LoweringError> {
    inline_component_body_with_arrays(
        comp_name,
        template,
        template_args,
        &HashMap::new(),
        ctx,
        span,
    )
}

/// Inline a component body, passing both scalar and array template arguments.
///
/// `array_args` maps parameter names to their compile-time array values
/// (e.g. `"C" → POSEIDON_C(t)` result).  These are injected into the
/// sub-template's `known_array_values` so that `C[expr]` resolves.
///
/// `const_inputs` maps signal input names (unmangled) to their constant
/// values.  These are injected into `known_constants` so the lowerer
/// emits `Const` instead of `Input` for those signals, enabling full
/// constant propagation through the sub-template body.
pub fn inline_component_body_with_arrays<'a>(
    comp_name: &str,
    template: &'a TemplateDef,
    template_args: &[CircuitExpr],
    array_args: &HashMap<String, EvalValue>,
    ctx: &mut LoweringContext<'a>,
    span: &diagnostics::Span,
) -> Result<Vec<CircuitNode>, LoweringError> {
    inline_component_body_impl(
        comp_name,
        template,
        template_args,
        array_args,
        &HashMap::new(),
        ctx,
        span,
    )
}

/// Inline with constant signal input propagation.
pub fn inline_component_body_with_const_inputs<'a>(
    comp_name: &str,
    template: &'a TemplateDef,
    template_args: &[CircuitExpr],
    array_args: &HashMap<String, EvalValue>,
    const_inputs: &HashMap<String, FieldConst>,
    ctx: &mut LoweringContext<'a>,
    span: &diagnostics::Span,
) -> Result<Vec<CircuitNode>, LoweringError> {
    inline_component_body_impl(
        comp_name,
        template,
        template_args,
        array_args,
        const_inputs,
        ctx,
        span,
    )
}

fn inline_component_body_impl<'a>(
    comp_name: &str,
    template: &'a TemplateDef,
    template_args: &[CircuitExpr],
    array_args: &HashMap<String, EvalValue>,
    const_inputs: &HashMap<String, FieldConst>,
    ctx: &mut LoweringContext<'a>,
    span: &diagnostics::Span,
) -> Result<Vec<CircuitNode>, LoweringError> {
    // Custom templates generate Plonk custom gates, not R1CS constraints.
    if template.modifiers.custom {
        return Err(LoweringError::with_code(
            format!(
                "template `{}` is declared as `custom` which generates Plonk custom gates; \
                 custom templates are not supported in R1CS mode — use a standard template instead",
                template.name
            ),
            "E205",
            span,
        ));
    }

    // Check recursion depth
    if ctx.inline_depth >= super::context::MAX_INLINE_DEPTH {
        return Err(LoweringError::new(
            format!(
                "component inlining depth limit ({}) exceeded — \
                 possible recursion via `{}`",
                super::context::MAX_INLINE_DEPTH,
                template.name,
            ),
            span,
        ));
    }
    ctx.inline_depth += 1;

    // Build parameter substitution map: param_name → arg_expr
    let mut param_subs: HashMap<String, CircuitExpr> = HashMap::new();
    for (i, param) in template.params.iter().enumerate() {
        if let Some(arg) = template_args.get(i) {
            param_subs.insert(param.clone(), arg.clone());
        }
    }

    // Extract param values from template args for cache key + stride computation.
    let mut param_values: HashMap<String, FieldConst> = HashMap::new();
    for (i, param) in template.params.iter().enumerate() {
        if let Some(arg) = template_args.get(i) {
            match arg {
                CircuitExpr::Const(fc) => {
                    param_values.insert(param.clone(), *fc);
                }
                CircuitExpr::Capture(name) | CircuitExpr::Var(name) => {
                    if let Some(&val) = ctx.param_values.get(name) {
                        param_values.insert(param.clone(), val);
                    }
                }
                other => {
                    if let Some(val) = try_eval_circuit_expr_fc(other, &ctx.param_values) {
                        param_values.insert(param.clone(), val);
                    }
                }
            }
        }
    }

    // Check body cache: only cache when const_inputs and array_args are empty,
    // since those guarantee identical lowered output for the same (template, params).
    let cacheable = const_inputs.is_empty() && array_args.is_empty();
    if cacheable {
        let cache_key = build_cache_key(&template.name, &param_values);
        if ctx.body_cache.contains_key(&cache_key) {
            // This `(template, params)` body was already lowered. Instead
            // of materializing a fresh name-mangled copy into the parent
            // body for every instance, promote the shared unmangled body
            // once and emit a single `ComponentCall` referencing it. The
            // instantiator re-runs the same canonical mangle when it
            // expands the call, so emitted constraints are byte-identical
            // to inlining — only the materialization is deferred, keeping
            // the parent body proportional to instance count rather than
            // instance count × body size.
            if !ctx.component_bodies.contains_key(&cache_key) {
                if let Some(body) = ctx.body_cache.get(&cache_key).cloned() {
                    ctx.component_bodies.insert(cache_key.clone(), body);
                }
            }
            ctx.inline_depth -= 1;
            return Ok(vec![CircuitNode::ComponentCall {
                body_key: cache_key,
                comp_name: comp_name.to_string(),
                param_subs: param_subs
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                span: None,
            }]);
        }
    }

    // Cache miss — full lowering

    // Build env for the sub-template (original signal names). Mark
    // it as inlined so the loop classifier knows the parent's
    // signal-array declarations and component bindings aren't in
    // scope here, and forces unroll for any indexed-assignment loop
    // (the SymbolicIndexedEffect path can't see across the inline
    // boundary).
    let mut env = LoweringEnv::new();
    env.is_inlined = true;

    let signals = collect_signal_names(&template.body.stmts);
    for (name, sig_type) in &signals {
        match sig_type {
            crate::ast::SignalType::Input => {
                env.inputs.insert(name.clone());
            }
            crate::ast::SignalType::Output | crate::ast::SignalType::Intermediate => {
                env.locals.insert(name.clone());
            }
        }
    }
    for param in &template.params {
        // Don't add array params as captures — they're resolved via known_array_values
        if !array_args.contains_key(param) {
            env.captures.insert(param.clone());
        }
    }

    // Inject array args into the sub-template's known_array_values
    for (name, val) in array_args {
        env.known_array_values.insert(name.clone(), val.clone());
    }

    // Inject constant signal inputs so the lowerer emits `Const` instead
    // of `Input` for these signals. This enables constant propagation
    // through sub-template bodies (e.g., Montgomery operations with known
    // base points collapse to zero constraints).
    for (name, &val) in const_inputs {
        env.known_constants.insert(name.clone(), val);
    }

    // Save parent param_values and inject sub-template values
    let saved_params = ctx.param_values.clone();
    ctx.param_values = param_values.clone();

    // Inject template param values into known_constants so expressions like
    // `nWindows` resolve to Const during body lowering.
    for (name, &val) in &param_values {
        env.known_constants.insert(name.clone(), val);
    }

    // Pre-evaluate compile-time var declarations (single pass, arrays + scalars)
    let precomputed =
        super::utils::precompute_all(&template.body.stmts, &ctx.param_values, &ctx.functions);
    // Find vars that are reassigned after their declaration (e.g., `lc1 += ...`,
    // `e2 = e2 + e2`). These must NOT be injected into known_constants because
    // they change value during the body lowering.
    let reassigned = find_reassigned_vars(&template.body.stmts);
    for (name, val) in &precomputed.scalars {
        ctx.param_values.insert(name.clone(), *val);
        // Only inject into known_constants if the var is never reassigned.
        // This enables constant folding for true constants like `var A = ...`
        // in MontgomeryDouble, without breaking accumulators like `lc1`.
        if !reassigned.contains(name) {
            env.known_constants.insert(name.clone(), *val);
        }
    }
    for (name, val) in precomputed.arrays {
        env.known_array_values.insert(name, val);
    }

    // Register multi-dimensional array strides for linearized indexing
    let stride_map = extract_signal_strides(template, &ctx.param_values);
    for (name, strides) in &stride_map {
        env.strides.insert(name.clone(), strides.clone());
    }

    // Register signal array sizes so that resolve_array_element works
    // (e.g., `xL[i-1]` resolves to `xL_4` during loop unrolling)
    let array_sizes = extract_signal_array_sizes(template, &ctx.param_values);
    for (signal_name, total_size) in array_sizes {
        env.arrays.insert(signal_name.clone(), total_size);
        for i in 0..total_size {
            env.locals.insert(format!("{signal_name}_{i}"));
        }
    }

    // Lower template body with original names
    let nodes = lower_stmts(&template.body.stmts, &mut env, ctx)?;

    // Restore parent param_values
    ctx.param_values = saved_params;

    // Cache the unmangled body for future instances — but only when
    // constant-output propagation over it is a no-op. The eager
    // inline path runs `propagate_const_nodes` over the *mangled*
    // body, lifting that instance's constant outputs into the parent
    // env under prefixed names. A deferred `ComponentCall` skips that
    // (the body is expanded later, unmangled-then-mangled at
    // instantiate), so a body that lifts constants must NOT be
    // promoted: re-lower it per instance instead. Dry-running the
    // propagation here makes every cached body a provable no-op, so
    // every later HIT→ComponentCall promotion is sound by
    // construction. (`const_inputs`/`array_args` emptiness gates the
    // *inputs*; this gates the *outputs*, which is the actual
    // soundness condition.)
    if cacheable {
        let mut probe_env = LoweringEnv::new();
        super::statements::wiring::propagate_const_nodes(&nodes, &mut probe_env);
        if probe_env.known_constants.is_empty() {
            let cache_key = build_cache_key(&template.name, &param_values);
            ctx.body_cache.insert(cache_key, nodes.clone());
        }
    }

    // Mangle all names and substitute captures
    let mangled = mangle_nodes(&nodes, comp_name, &param_subs);

    ctx.inline_depth -= 1;
    Ok(mangled)
}

/// Register a component's output and intermediate signals as locals in the
/// parent environment (with mangled names).
pub fn register_component_locals(
    comp_name: &str,
    template: &TemplateDef,
    template_args: &[CircuitExpr],
    parent_env: &mut LoweringEnv,
) {
    let signals = collect_signal_names(&template.body.stmts);
    for (name, sig_type) in &signals {
        match sig_type {
            crate::ast::SignalType::Input
            | crate::ast::SignalType::Output
            | crate::ast::SignalType::Intermediate => {
                parent_env.locals.insert(format!("{comp_name}.{name}"));
            }
        }
    }

    // Propagate stride info for multi-dim arrays to parent env
    let param_values: HashMap<String, FieldConst> = template
        .params
        .iter()
        .enumerate()
        .filter_map(|(i, param)| {
            template_args
                .get(i)
                .and_then(|arg| {
                    if let CircuitExpr::Const(fc) = arg {
                        Some(*fc)
                    } else {
                        None
                    }
                })
                .map(|val| (param.clone(), val))
        })
        .collect();

    let stride_map = extract_signal_strides(template, &param_values);
    for (signal_name, strides) in stride_map {
        parent_env
            .strides
            .insert(format!("{comp_name}.{signal_name}"), strides);
    }

    // Register array sizes and individual element names for component signals
    let array_sizes = extract_signal_array_sizes(template, &param_values);
    for (signal_name, total_size) in array_sizes {
        let mangled_array = format!("{comp_name}.{signal_name}");
        parent_env.arrays.insert(mangled_array.clone(), total_size);
        // Register individual elements as locals: mux.out_0, mux.out_1, ...
        for i in 0..total_size {
            parent_env.locals.insert(format!("{mangled_array}_{i}"));
        }
    }
}

/// Try to evaluate a `CircuitExpr` to a `FieldConst` using a context of known values.
///
/// Handles `Const`, `Var`/`Capture` lookups, and basic arithmetic (`Add`, `Sub`, `Mul`, `Div`).
/// Used to resolve expression-valued template args like `(r+1)*t`.
fn try_eval_circuit_expr_fc(
    expr: &CircuitExpr,
    context: &HashMap<String, FieldConst>,
) -> Option<FieldConst> {
    use super::utils::BigVal;
    match expr {
        CircuitExpr::Const(fc) => Some(*fc),
        CircuitExpr::Var(name) | CircuitExpr::Capture(name) => context.get(name).copied(),
        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = BigVal::from_field_const(try_eval_circuit_expr_fc(lhs, context)?);
            let r = BigVal::from_field_const(try_eval_circuit_expr_fc(rhs, context)?);
            let result = match op {
                CircuitBinOp::Add => l.add(r),
                CircuitBinOp::Sub => l.sub(r),
                CircuitBinOp::Mul => l.mul(r),
                _ => return None,
            };
            Some(result.to_field_const())
        }
        CircuitExpr::IntDiv { lhs, rhs, .. } => {
            let l = BigVal::from_field_const(try_eval_circuit_expr_fc(lhs, context)?);
            let r = BigVal::from_field_const(try_eval_circuit_expr_fc(rhs, context)?);
            Some(l.div(r)?.to_field_const())
        }
        CircuitExpr::IntMod { lhs, rhs, .. } => {
            let l = BigVal::from_field_const(try_eval_circuit_expr_fc(lhs, context)?);
            let r = BigVal::from_field_const(try_eval_circuit_expr_fc(rhs, context)?);
            Some(l.rem(r)?.to_field_const())
        }
        _ => None,
    }
}

/// Find variables that are reassigned after their initial declaration.
///
/// Scans statements recursively for `Substitution { target: Ident(name), op: Assign, ... }`
/// and `CompoundAssign { target: Ident(name), ... }`. Returns the set of var names that
/// are targets of such reassignment. These vars must NOT be injected into
/// `known_constants` because their value changes during lowering.
pub(super) fn find_reassigned_vars(stmts: &[crate::ast::Stmt]) -> HashSet<String> {
    let mut reassigned = HashSet::new();
    let mut declared = HashSet::new();
    // Vars declared via `var X;` (no initializer) are treated as a
    // deferred init — the first top-level `X = expr;` is the logical
    // initializer, not a reassignment. This matches circomlib's SHA256
    // idiom (`var nBlocks; ...; nBlocks = (nBits+64)\512 + 1;`) and
    // lines up with `precompute_all`, which captures exactly that
    // first assignment as the var's compile-time value.
    let mut uninitialized = HashSet::new();
    scan_reassignments(stmts, &mut declared, &mut uninitialized, &mut reassigned);
    reassigned
}

fn scan_reassignments(
    stmts: &[crate::ast::Stmt],
    declared: &mut HashSet<String>,
    uninitialized: &mut HashSet<String>,
    reassigned: &mut HashSet<String>,
) {
    use crate::ast::{AssignOp, Stmt};
    for stmt in stmts {
        match stmt {
            Stmt::VarDecl { names, init, .. } => {
                for name in names {
                    declared.insert(name.clone());
                    if init.is_none() {
                        uninitialized.insert(name.clone());
                    }
                }
            }
            Stmt::Substitution {
                target,
                op: AssignOp::Assign,
                ..
            } => {
                if let Some(name) = super::utils::extract_ident_name(target) {
                    if uninitialized.remove(&name) {
                        // First assignment to a `var X;` — treat as init.
                        continue;
                    }
                    if declared.contains(&name) {
                        reassigned.insert(name);
                    }
                }
            }
            Stmt::CompoundAssign { target, .. } => {
                if let Some(name) = super::utils::extract_ident_name(target) {
                    reassigned.insert(name);
                }
            }
            Stmt::For {
                init, body, step, ..
            } => {
                scan_reassignments(
                    std::slice::from_ref(init.as_ref()),
                    declared,
                    uninitialized,
                    reassigned,
                );
                scan_reassignments(&body.stmts, declared, uninitialized, reassigned);
                scan_reassignments(
                    std::slice::from_ref(step.as_ref()),
                    declared,
                    uninitialized,
                    reassigned,
                );
            }
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                scan_reassignments(&then_body.stmts, declared, uninitialized, reassigned);
                if let Some(crate::ast::ElseBranch::Block(block)) = else_body {
                    scan_reassignments(&block.stmts, declared, uninitialized, reassigned);
                } else if let Some(crate::ast::ElseBranch::IfElse(inner)) = else_body {
                    scan_reassignments(
                        std::slice::from_ref(inner.as_ref()),
                        declared,
                        uninitialized,
                        reassigned,
                    );
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                scan_reassignments(&body.stmts, declared, uninitialized, reassigned);
            }
            Stmt::Block(block) => {
                scan_reassignments(&block.stmts, declared, uninitialized, reassigned);
            }
            _ => {}
        }
    }
}

/// Build a cache key for the body cache from template name and param values.
///
/// The key uniquely identifies the lowered body for a (template, params)
/// combination. Templates with the same name and same param values produce
/// identical lowered bodies (before mangling), so the cached result can be
/// reused by just re-mangling with a different component prefix.
fn build_cache_key(template_name: &str, params: &HashMap<String, FieldConst>) -> String {
    if params.is_empty() {
        return template_name.to_string();
    }
    let mut pairs: Vec<_> = params.iter().collect();
    pairs.sort_by_key(|(k, _)| k.as_str());
    let mut key = template_name.to_string();
    for (name, val) in pairs {
        use std::fmt::Write;
        // Use u64 for small values, Debug repr for large ones
        if let Some(v) = val.to_u64() {
            let _ = write!(key, ":{name}={v}");
        } else {
            let _ = write!(key, ":{name}={val:?}");
        }
    }
    key
}
