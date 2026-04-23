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

use ir_forge::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp,
    FieldConst, ForRange,
};

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
        if let Some(cached_body) = ctx.body_cache.get(&cache_key) {
            let mangled = mangle_nodes(cached_body, comp_name, &param_subs);

            ctx.inline_depth -= 1;
            return Ok(mangled);
        }
    }

    // Cache miss — full lowering

    // Build env for the sub-template (original signal names)
    let mut env = LoweringEnv::new();

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

    // Cache the unmangled body for future instances
    if cacheable {
        let cache_key = build_cache_key(&template.name, &param_values);
        ctx.body_cache.insert(cache_key, nodes.clone());
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

// ---------------------------------------------------------------------------
// Name mangling
// ---------------------------------------------------------------------------

/// Mangle a list of CircuitNodes: prefix all names and substitute captures.
fn mangle_nodes(
    nodes: &[CircuitNode],
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> Vec<CircuitNode> {
    nodes
        .iter()
        .map(|n| mangle_node(n, prefix, param_subs))
        .collect()
}

fn mangle_node(
    node: &CircuitNode,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> CircuitNode {
    match node {
        CircuitNode::Let { name, value, span } => CircuitNode::Let {
            name: mangle_name(prefix, name),
            value: mangle_expr(value, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::LetArray {
            name,
            elements,
            span,
        } => CircuitNode::LetArray {
            name: mangle_name(prefix, name),
            elements: elements
                .iter()
                .map(|e| mangle_expr(e, prefix, param_subs))
                .collect(),
            span: span.clone(),
        },
        CircuitNode::AssertEq {
            lhs,
            rhs,
            message,
            span,
        } => CircuitNode::AssertEq {
            lhs: mangle_expr(lhs, prefix, param_subs),
            rhs: mangle_expr(rhs, prefix, param_subs),
            message: message.clone(),
            span: span.clone(),
        },
        CircuitNode::Assert {
            expr,
            message,
            span,
        } => CircuitNode::Assert {
            expr: mangle_expr(expr, prefix, param_subs),
            message: message.clone(),
            span: span.clone(),
        },
        CircuitNode::For {
            var,
            range,
            body,
            span,
        } => CircuitNode::For {
            var: mangle_name(prefix, var),
            range: mangle_range(range, prefix, param_subs),
            body: mangle_nodes(body, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            span,
        } => CircuitNode::If {
            cond: mangle_expr(cond, prefix, param_subs),
            then_body: mangle_nodes(then_body, prefix, param_subs),
            else_body: mangle_nodes(else_body, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::Expr { expr, span } => CircuitNode::Expr {
            expr: mangle_expr(expr, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::Decompose {
            name,
            value,
            num_bits,
            span,
        } => CircuitNode::Decompose {
            name: mangle_name(prefix, name),
            value: mangle_expr(value, prefix, param_subs),
            num_bits: *num_bits,
            span: span.clone(),
        },
        CircuitNode::WitnessHint { name, hint, span } => CircuitNode::WitnessHint {
            name: mangle_name(prefix, name),
            hint: mangle_expr(hint, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::LetIndexed {
            array,
            index,
            value,
            span,
        } => CircuitNode::LetIndexed {
            array: mangle_name(prefix, array),
            index: mangle_expr(index, prefix, param_subs),
            value: mangle_expr(value, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::WitnessHintIndexed {
            array,
            index,
            hint,
            span,
        } => CircuitNode::WitnessHintIndexed {
            array: mangle_name(prefix, array),
            index: mangle_expr(index, prefix, param_subs),
            hint: mangle_expr(hint, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::WitnessCall {
            output_bindings,
            input_signals,
            program_bytes,
            span,
        } => CircuitNode::WitnessCall {
            output_bindings: output_bindings
                .iter()
                .map(|n| mangle_name(prefix, n))
                .collect(),
            input_signals: input_signals
                .iter()
                .map(|e| mangle_expr(e, prefix, param_subs))
                .collect(),
            // Opaque Artik bytecode is unaffected by template
            // mangling — its internal signal / slot ids are set at
            // lift time and do not collide with outer-template names.
            program_bytes: program_bytes.clone(),
            span: span.clone(),
        },
    }
}

fn mangle_expr(
    expr: &CircuitExpr,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> CircuitExpr {
    match expr {
        // Leaf nodes
        CircuitExpr::Const(c) => CircuitExpr::Const(*c),
        CircuitExpr::Input(name) => {
            // Input signals in inlined body → Var with mangled name
            // (they are wired from outside as Let bindings)
            CircuitExpr::Var(mangle_name(prefix, name))
        }
        CircuitExpr::Var(name) => CircuitExpr::Var(mangle_name(prefix, name)),
        CircuitExpr::Capture(name) => {
            // Substitute capture with template argument expression
            if let Some(sub) = param_subs.get(name) {
                sub.clone()
            } else {
                // Unknown capture — keep as-is with mangled name
                CircuitExpr::Capture(mangle_name(prefix, name))
            }
        }

        // Binary ops
        CircuitExpr::BinOp { op, lhs, rhs } => CircuitExpr::BinOp {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },
        CircuitExpr::Comparison { op, lhs, rhs } => CircuitExpr::Comparison {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },
        CircuitExpr::BoolOp { op, lhs, rhs } => CircuitExpr::BoolOp {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },

        // Unary
        CircuitExpr::UnaryOp { op, operand } => CircuitExpr::UnaryOp {
            op: *op,
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
        },

        // Mux
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => CircuitExpr::Mux {
            cond: Box::new(mangle_expr(cond, prefix, param_subs)),
            if_true: Box::new(mangle_expr(if_true, prefix, param_subs)),
            if_false: Box::new(mangle_expr(if_false, prefix, param_subs)),
        },

        // Crypto
        CircuitExpr::PoseidonHash { left, right } => CircuitExpr::PoseidonHash {
            left: Box::new(mangle_expr(left, prefix, param_subs)),
            right: Box::new(mangle_expr(right, prefix, param_subs)),
        },
        CircuitExpr::PoseidonMany(args) => CircuitExpr::PoseidonMany(
            args.iter()
                .map(|a| mangle_expr(a, prefix, param_subs))
                .collect(),
        ),
        CircuitExpr::RangeCheck { value, bits } => CircuitExpr::RangeCheck {
            value: Box::new(mangle_expr(value, prefix, param_subs)),
            bits: *bits,
        },
        CircuitExpr::MerkleVerify {
            root,
            leaf,
            path,
            indices,
        } => CircuitExpr::MerkleVerify {
            root: Box::new(mangle_expr(root, prefix, param_subs)),
            leaf: Box::new(mangle_expr(leaf, prefix, param_subs)),
            path: mangle_name(prefix, path),
            indices: mangle_name(prefix, indices),
        },

        // Array
        CircuitExpr::ArrayIndex { array, index } => CircuitExpr::ArrayIndex {
            array: mangle_name(prefix, array),
            index: Box::new(mangle_expr(index, prefix, param_subs)),
        },
        CircuitExpr::ArrayLen(name) => CircuitExpr::ArrayLen(mangle_name(prefix, name)),

        // Power
        CircuitExpr::Pow { base, exp } => CircuitExpr::Pow {
            base: Box::new(mangle_expr(base, prefix, param_subs)),
            exp: *exp,
        },

        // Integer ops
        CircuitExpr::IntDiv { lhs, rhs, max_bits } => CircuitExpr::IntDiv {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            max_bits: *max_bits,
        },
        CircuitExpr::IntMod { lhs, rhs, max_bits } => CircuitExpr::IntMod {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            max_bits: *max_bits,
        },

        // Bitwise ops
        CircuitExpr::BitAnd { lhs, rhs, num_bits } => CircuitExpr::BitAnd {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitOr { lhs, rhs, num_bits } => CircuitExpr::BitOr {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitXor { lhs, rhs, num_bits } => CircuitExpr::BitXor {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitNot { operand, num_bits } => CircuitExpr::BitNot {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::ShiftR {
            operand,
            shift,
            num_bits,
        } => CircuitExpr::ShiftR {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            shift: Box::new(mangle_expr(shift, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::ShiftL {
            operand,
            shift,
            num_bits,
        } => CircuitExpr::ShiftL {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            shift: Box::new(mangle_expr(shift, prefix, param_subs)),
            num_bits: *num_bits,
        },
    }
}

fn mangle_range(
    range: &ForRange,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> ForRange {
    match range {
        ForRange::Literal { start, end } => ForRange::Literal {
            start: *start,
            end: *end,
        },
        ForRange::WithCapture { start, end_capture } => {
            match param_subs.get(end_capture) {
                // Substitution is a constant → fold to Literal
                Some(CircuitExpr::Const(fc)) => {
                    if let Some(end) = fc.to_u64() {
                        return ForRange::Literal { start: *start, end };
                    }
                    ForRange::WithCapture {
                        start: *start,
                        end_capture: mangle_name(prefix, end_capture),
                    }
                }
                // Substitution is an expression (e.g., Capture("n") + Const(1)
                // from `Num2Bits(n+1)`) → use WithExpr so the instantiator
                // can evaluate it when capture values are known
                Some(expr) => ForRange::WithExpr {
                    start: *start,
                    end_expr: Box::new(expr.clone()),
                },
                // No substitution → mangle capture name
                None => ForRange::WithCapture {
                    start: *start,
                    end_capture: mangle_name(prefix, end_capture),
                },
            }
        }
        ForRange::WithExpr { start, end_expr } => ForRange::WithExpr {
            start: *start,
            end_expr: Box::new(mangle_expr(end_expr, prefix, param_subs)),
        },
        ForRange::Array(name) => ForRange::Array(mangle_name(prefix, name)),
    }
}

/// Mangle a variable name with the component prefix.
///
/// Uses `.` as separator to match the DotAccess convention in
/// `expressions.rs`: `comp.field` → `comp.field`. The `.` character
/// cannot appear in Circom identifiers, making collisions impossible.
fn mangle_name(prefix: &str, name: &str) -> String {
    format!("{prefix}.{name}")
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

// Suppress unused warnings for operator enums that are used indirectly
// through the CircuitExpr/CircuitNode match arms above.
#[allow(unused_imports)]
use {CircuitBinOp as _, CircuitBoolOp as _, CircuitCmpOp as _, CircuitUnaryOp as _};

#[cfg(test)]
mod tests {
    use super::*;
    use ir_forge::types::FieldConst;

    #[test]
    fn mangle_name_format() {
        assert_eq!(mangle_name("c", "a"), "c.a");
        assert_eq!(mangle_name("comp", "signal"), "comp.signal");
    }

    #[test]
    fn mangle_expr_input_becomes_var() {
        let expr = CircuitExpr::Input("a".to_string());
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Var("c.a".to_string()));
    }

    #[test]
    fn mangle_expr_var_prefixed() {
        let expr = CircuitExpr::Var("x".to_string());
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Var("c.x".to_string()));
    }

    #[test]
    fn mangle_expr_capture_substituted() {
        let mut subs = HashMap::new();
        subs.insert("n".to_string(), CircuitExpr::Const(FieldConst::from_u64(8)));
        let expr = CircuitExpr::Capture("n".to_string());
        let result = mangle_expr(&expr, "c", &subs);
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(8)));
    }

    #[test]
    fn mangle_expr_const_unchanged() {
        let expr = CircuitExpr::Const(FieldConst::from_u64(42));
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn mangle_node_let() {
        let node = CircuitNode::Let {
            name: "x".to_string(),
            value: CircuitExpr::Input("a".to_string()),
            span: None,
        };
        let result = mangle_node(&node, "c", &HashMap::new());
        match result {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "c.x");
                assert_eq!(value, CircuitExpr::Var("c.a".to_string()));
            }
            _ => panic!("expected Let"),
        }
    }

    #[test]
    fn mangle_node_assert_eq() {
        let node = CircuitNode::AssertEq {
            lhs: CircuitExpr::Var("out".to_string()),
            rhs: CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(CircuitExpr::Input("a".to_string())),
                rhs: Box::new(CircuitExpr::Input("b".to_string())),
            },
            message: None,
            span: None,
        };
        let result = mangle_node(&node, "m", &HashMap::new());
        match result {
            CircuitNode::AssertEq { lhs, rhs, .. } => {
                assert_eq!(lhs, CircuitExpr::Var("m.out".to_string()));
                match rhs {
                    CircuitExpr::BinOp { lhs, rhs, .. } => {
                        assert_eq!(*lhs, CircuitExpr::Var("m.a".to_string()));
                        assert_eq!(*rhs, CircuitExpr::Var("m.b".to_string()));
                    }
                    _ => panic!("expected BinOp"),
                }
            }
            _ => panic!("expected AssertEq"),
        }
    }

    #[test]
    fn mangle_for_range_literal_unchanged() {
        let range = ForRange::Literal { start: 0, end: 8 };
        let result = mangle_range(&range, "c", &HashMap::new());
        assert_eq!(result, ForRange::Literal { start: 0, end: 8 });
    }

    #[test]
    fn mangle_for_range_capture_with_known_const() {
        let mut subs = HashMap::new();
        subs.insert(
            "n".to_string(),
            CircuitExpr::Const(FieldConst::from_u64(16)),
        );
        let range = ForRange::WithCapture {
            start: 0,
            end_capture: "n".to_string(),
        };
        let result = mangle_range(&range, "c", &subs);
        assert_eq!(result, ForRange::Literal { start: 0, end: 16 });
    }
}
