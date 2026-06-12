//! Instance replay of compiled [`HintTemplate`]s.
//!
//! Where the reference interpreter expands every `ComponentCall` into
//! a freshly mangled body clone, the replay walks the SHARED compiled
//! template under a per-instance prefix: each body-local [`NameId`]
//! resolves to a global value slot at most once per instance, and all
//! further accesses are dense-vector reads/writes.
//!
//! Semantics are an exact mirror of the reference walk, including its
//! edges: an unevaluable hint is silently and permanently skipped, an
//! `If` whose condition cannot be evaluated walks BOTH branches, loop
//! variables persist in the env after the loop, later writes overwrite
//! earlier values, and indexed element names share the flat textual
//! namespace with scalars. `compute_witness_hints_reference` in
//! [`super::compute`] pins this equivalence in tests.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;

use ir_forge::types::{CircuitBinOp, ProveIR};
use memory::{FieldBackend, FieldElement};

use super::error::WitnessError;
use super::replay_eval::{eval, eval_u64};
use super::slot_env::SlotEnv;
use super::template::{compile_body, ExprId, HintTemplate, NameId, TExpr, TOp, TRange};

/// Shared replay state: the slot env, the global captures map, the
/// compiled component bodies, the Artik memo, and a scratch buffer
/// for building qualified names without per-access allocation.
pub(super) struct Cx<'t, 'm, F: FieldBackend> {
    pub env: SlotEnv<F>,
    pub captures: &'t HashMap<String, u64>,
    pub templates: &'t HashMap<&'t str, HintTemplate>,
    pub memo: Option<&'m mut artik::ArtikMemo<F>>,
    pub scratch: String,
}

/// One component instance: a template walked under a prefix.
///
/// `subs` carries the instance's template-parameter substitutions:
/// the argument expression (an id into the PARENT's template arena,
/// for the const-only range evaluator) plus its value, evaluated once
/// at instance creation. Pre-evaluation is exact because every write
/// during the child walk is confined to the child's dotted prefix
/// subtree, so the parent-visible env is frozen while the child runs,
/// and expression evaluation is pure. (The reference interpreter
/// instead re-evaluates the substituted expression at each use site —
/// same values, but `ACH_WITNESS_PROFILE` div counters may tally a
/// different number of evaluations.)
pub(super) struct Instance<'t, 'p, F: FieldBackend> {
    pub prefix: String,
    pub template: &'t HintTemplate,
    /// NameId -> global slot, resolved lazily, at most once per name.
    pub resolve: RefCell<Vec<Option<u32>>>,
    pub subs: HashMap<String, SubBinding<F>>,
    pub parent: Option<&'p Instance<'t, 'p, F>>,
}

pub(super) struct SubBinding<F: FieldBackend> {
    /// The argument expression, in the parent instance's arena.
    pub expr: ExprId,
    /// Its value in the parent context at instance creation.
    pub value: Option<FieldElement<F>>,
}

impl<'t, 'p, F: FieldBackend> Instance<'t, 'p, F> {
    fn new(
        prefix: String,
        template: &'t HintTemplate,
        subs: HashMap<String, SubBinding<F>>,
        parent: Option<&'p Instance<'t, 'p, F>>,
    ) -> Self {
        Self {
            prefix,
            template,
            resolve: RefCell::new(vec![None; template.names.len()]),
            subs,
            parent,
        }
    }
}

/// Build `prefix.name` (or `name` for the unmangled top level) into
/// the scratch buffer.
fn qualify_into(scratch: &mut String, prefix: &str, name: &str) {
    scratch.clear();
    if !prefix.is_empty() {
        scratch.push_str(prefix);
        scratch.push('.');
    }
    scratch.push_str(name);
}

/// Global slot for `inst`-qualified `nid`, resolved through the
/// instance cache.
pub(super) fn resolve<F: FieldBackend>(
    nid: NameId,
    inst: &Instance<'_, '_, F>,
    cx: &mut Cx<'_, '_, F>,
) -> u32 {
    if let Some(s) = inst.resolve.borrow()[nid as usize] {
        return s;
    }
    qualify_into(
        &mut cx.scratch,
        &inst.prefix,
        &inst.template.names[nid as usize],
    );
    let s = cx.env.slot(&cx.scratch);
    inst.resolve.borrow_mut()[nid as usize] = Some(s);
    s
}

/// Entry point: compile every body once, replay the top body as the
/// degenerate instance (empty prefix, no substitutions), flatten.
pub(super) fn compute_via_templates<F: FieldBackend>(
    prove_ir: &ProveIR,
    inputs: &HashMap<String, FieldElement<F>>,
    captures: &HashMap<String, u64>,
    memo: Option<&mut artik::ArtikMemo<F>>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessError> {
    let top = compile_body(&prove_ir.body);
    let templates: HashMap<&str, HintTemplate> = prove_ir
        .component_bodies
        .iter()
        .map(|(key, body)| (key.as_str(), compile_body(body)))
        .collect();

    // Seed exactly as the reference walk does: all inputs, then
    // captures without overwriting an input of the same name.
    let mut env = SlotEnv::new();
    for (name, val) in inputs {
        env.write(name, *val);
    }
    for (name, val) in captures {
        let slot = env.slot(name);
        if env.get(slot).is_none() {
            env.set(slot, FieldElement::<F>::from_u64(*val));
        }
    }

    let mut cx = Cx {
        env,
        captures,
        templates: &templates,
        memo,
        scratch: String::new(),
    };
    let top_inst = Instance::new(String::new(), &top, HashMap::new(), None);
    replay_ops(&top.ops, &top_inst, &mut cx)?;
    Ok(cx.env.materialize())
}

pub(super) fn replay_ops<'t, F: FieldBackend>(
    ops: &'t [TOp],
    inst: &Instance<'t, '_, F>,
    cx: &mut Cx<'t, '_, F>,
) -> Result<(), WitnessError> {
    for op in ops {
        match op {
            TOp::Let { name, value } | TOp::WitnessHint { name, hint: value } => {
                if let Some(val) = eval(*value, inst, cx) {
                    let slot = resolve(*name, inst, cx);
                    cx.env.set(slot, val);
                }
            }
            TOp::LetIndexed {
                array,
                index,
                value,
            }
            | TOp::WitnessHintIndexed {
                array,
                index,
                hint: value,
            } => {
                if let (Some(idx), Some(val)) = (eval_u64(*index, inst, cx), eval(*value, inst, cx))
                {
                    qualify_into(
                        &mut cx.scratch,
                        &inst.prefix,
                        &inst.template.names[*array as usize],
                    );
                    let _ = write!(cx.scratch, "_{idx}");
                    let slot = cx.env.slot(&cx.scratch);
                    cx.env.set(slot, val);
                }
            }
            TOp::LetArray { name, elements } => {
                for (i, elem) in elements.iter().enumerate() {
                    if let Some(val) = eval(*elem, inst, cx) {
                        qualify_into(
                            &mut cx.scratch,
                            &inst.prefix,
                            &inst.template.names[*name as usize],
                        );
                        let _ = write!(cx.scratch, "_{i}");
                        let slot = cx.env.slot(&cx.scratch);
                        cx.env.set(slot, val);
                    }
                }
            }
            TOp::For { var, range, body } => {
                let (start, end) = resolve_range(range, inst, cx);
                if let (Some(start), Some(end)) = (start, end) {
                    let var_slot = resolve(*var, inst, cx);
                    for i in start..end {
                        cx.env.set(var_slot, FieldElement::<F>::from_u64(i));
                        replay_ops(body, inst, cx)?;
                    }
                } else {
                    replay_ops(body, inst, cx)?;
                }
            }
            TOp::If {
                cond,
                then_body,
                else_body,
            } => {
                if let Some(val) = eval(*cond, inst, cx) {
                    if val != FieldElement::<F>::zero() {
                        replay_ops(then_body, inst, cx)?;
                    } else {
                        replay_ops(else_body, inst, cx)?;
                    }
                } else {
                    replay_ops(then_body, inst, cx)?;
                    replay_ops(else_body, inst, cx)?;
                }
            }
            TOp::Assert { expr, message } => {
                if let Some(val) = eval(*expr, inst, cx) {
                    if val == FieldElement::<F>::zero() {
                        let msg = message
                            .as_deref()
                            .unwrap_or("circom assert() failed during witness computation");
                        return Err(WitnessError {
                            message: msg.to_string(),
                        });
                    }
                }
            }
            TOp::WitnessCall {
                output_bindings,
                input_signals,
                program_bytes,
            } => {
                // Resolve input signals in order; if any is not yet
                // computed, skip this call permanently — exactly the
                // reference walk's behavior.
                let mut signal_vec: Vec<FieldElement<F>> = Vec::with_capacity(input_signals.len());
                let mut all_resolved = true;
                for expr in input_signals {
                    match eval(*expr, inst, cx) {
                        Some(v) => signal_vec.push(v),
                        None => {
                            all_resolved = false;
                            break;
                        }
                    }
                }
                if !all_resolved {
                    continue;
                }

                let mut slot_vec: Vec<FieldElement<F>> =
                    vec![FieldElement::<F>::zero(); output_bindings.len()];
                match cx.memo.as_deref_mut() {
                    Some(m) => m.run(program_bytes, &signal_vec, &mut slot_vec),
                    None => artik::execute_into(program_bytes, &signal_vec, &mut slot_vec),
                }
                .map_err(|e| WitnessError {
                    message: format!("Artik witness call failed: {e:?}"),
                })?;

                for (name, val) in output_bindings.iter().zip(slot_vec.iter()) {
                    let slot = resolve(*name, inst, cx);
                    cx.env.set(slot, *val);
                }
            }
            TOp::ComponentCall {
                body_key,
                comp_name,
                param_subs,
            } => {
                let template = cx
                    .templates
                    .get(body_key.as_str())
                    .ok_or_else(|| WitnessError {
                        message: format!("ComponentCall references unknown body key `{body_key}`"),
                    })?;
                qualify_into(
                    &mut cx.scratch,
                    &inst.prefix,
                    &inst.template.names[*comp_name as usize],
                );
                let child_prefix = cx.scratch.clone();
                // Last write wins on duplicate param names, matching
                // the reference walk's HashMap collect.
                let mut subs: HashMap<String, SubBinding<F>> =
                    HashMap::with_capacity(param_subs.len());
                for (param, expr) in param_subs {
                    let value = eval(*expr, inst, cx);
                    subs.insert(param.clone(), SubBinding { expr: *expr, value });
                }
                let child = Instance::new(child_prefix, template, subs, Some(inst));
                replay_ops(&template.ops, &child, cx)?;
            }
        }
    }
    Ok(())
}

/// Resolve a for-range to `(start, end)` bounds, mirroring the
/// composition of `mangle_range` (which substitutes the instance's
/// params into the range) with the reference walk's range arm.
fn resolve_range<F: FieldBackend>(
    range: &TRange,
    inst: &Instance<'_, '_, F>,
    cx: &mut Cx<'_, '_, F>,
) -> (Option<u64>, Option<u64>) {
    match range {
        TRange::Literal { start, end } => (Some(*start), Some(*end)),
        TRange::WithCapture { start, cap } => {
            let cap_name = &inst.template.names[*cap as usize];
            let end = match (inst.subs.get(cap_name.as_str()), inst.parent) {
                (Some(binding), Some(parent)) => {
                    match &parent.template.exprs[binding.expr as usize] {
                        // A constant argument folds the range to a
                        // literal bound; a constant that does not fit
                        // u64 leaves the capture name to be looked up
                        // (and in practice missed) in the captures map.
                        TExpr::Const(fc) => match fc.to_u64() {
                            Some(end) => Some(end),
                            None => captures_lookup(inst, cap_name, cx),
                        },
                        // A non-constant argument becomes a computed
                        // bound over the substituted expression. A
                        // capture CHAIN whose head is a non-u64
                        // constant resolves to None here without the
                        // captures-map fallback the collapsed textual
                        // substitution would take; capture values are
                        // u64, so the lowering cannot produce a
                        // qualified entry that case could hit.
                        _ => const_eval(binding.expr, parent, cx),
                    }
                }
                _ => captures_lookup(inst, cap_name, cx),
            };
            (Some(*start), end)
        }
        TRange::WithExpr { start, expr } => (Some(*start), const_eval(*expr, inst, cx)),
        TRange::Array => (None, None),
    }
}

/// `captures.get` under the instance-qualified capture name.
fn captures_lookup<F: FieldBackend>(
    inst: &Instance<'_, '_, F>,
    cap_name: &str,
    cx: &mut Cx<'_, '_, F>,
) -> Option<u64> {
    qualify_into(&mut cx.scratch, &inst.prefix, cap_name);
    cx.captures.get(cx.scratch.as_str()).copied()
}

/// Const-only u64 evaluator for loop bounds. Mirrors the reference
/// `eval_const_expr_u64`: constants, captures (resolved through the
/// substitution chain), and the four arithmetic operators; everything
/// else — including plain variables — is not a constant bound.
pub(super) fn const_eval<F: FieldBackend>(
    eid: ExprId,
    inst: &Instance<'_, '_, F>,
    cx: &mut Cx<'_, '_, F>,
) -> Option<u64> {
    match &inst.template.exprs[eid as usize] {
        TExpr::Const(fc) => fc.to_u64(),
        TExpr::Capture(nid) => {
            let name = &inst.template.names[*nid as usize];
            match (inst.subs.get(name.as_str()), inst.parent) {
                (Some(binding), Some(parent)) => const_eval(binding.expr, parent, cx),
                _ => captures_lookup(inst, name, cx),
            }
        }
        TExpr::BinOp { op, lhs, rhs } => {
            let l = const_eval(*lhs, inst, cx)?;
            let r = const_eval(*rhs, inst, cx)?;
            match op {
                CircuitBinOp::Add => Some(l.wrapping_add(r)),
                CircuitBinOp::Sub => Some(l.wrapping_sub(r)),
                CircuitBinOp::Mul => Some(l.wrapping_mul(r)),
                CircuitBinOp::Div => l.checked_div(r),
            }
        }
        _ => None,
    }
}
