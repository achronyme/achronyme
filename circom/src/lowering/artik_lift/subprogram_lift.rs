//! Multi-subprogram lift driver: turn a circom function body into an
//! Artik program whose entry subprogram is the function itself and
//! whose callee subprograms are every transitively-called circom
//! function, each reserved once per parameter signature and invoked
//! with a real Artik `Call`.

use std::collections::HashMap;

use diagnostics::Span;

use crate::ast::{FunctionDef, Stmt};
use crate::lowering::context::LoweringContext;

use super::{
    callee, driver, helpers, intrinsics, ArrayShape, ConstInt, LiftState, LiftedShape,
    LiftedWitnessCall, ParamShape, ReturnShape,
};

/// Loud-failure backstop for the callee drain. circom forbids
/// recursion and the registry deduplicates specializations, so the
/// pending queue is finite for well-formed input; this cap turns a
/// pathological non-terminating drain into a clean decline rather than
/// an unbounded loop.
const MAX_CALLEE_SUBPROGRAMS: usize = 4096;

/// Lift `body` into a multi-subprogram Artik program: the function
/// itself is the entry subprogram (signal-in / witness-out ABI, the
/// locked `LiftedWitnessCall` contract — `outputs` and `shape`
/// identical to the inlining path, only `program_bytes` differs), and
/// every transitively-called circom function becomes a callee
/// subprogram, reserved once per parameter signature and invoked with
/// a real Artik `Call`. Returns `None` for any shape this path does
/// not cover; the caller then falls back exactly as if the lift had
/// declined, so the inlining path is never regressed.
pub(super) fn try_lift_via_subprograms(
    function_name: &str,
    params: &[(String, ParamShape)],
    param_consts: &[Option<ConstInt>],
    body: &[Stmt],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<LiftedWitnessCall> {
    // A fixed-shape entry subprogram can only be reserved when every
    // array dimension in the body folds to a constant and the return
    // shape is resolvable. A runtime dimension or an unmodelled return
    // means the caller falls back exactly as if the lift had declined.
    let param_consts_map: HashMap<String, ConstInt> = params
        .iter()
        .zip(param_consts.iter())
        .filter_map(|((name, shape), c)| match (shape, c) {
            (ParamShape::Scalar, Some(v)) => Some((name.clone(), *v)),
            _ => None,
        })
        .collect();
    helpers::compute_dim_signature(body, &param_consts_map)?;
    // Built before the return-shape gate: a `return f(..)` forwarded
    // return resolves to f's shape, which the classifier reads from
    // this registry.
    let functions: HashMap<String, &FunctionDef> = ctx
        .functions
        .iter()
        .map(|(&k, &v)| (k.to_string(), v))
        .collect();
    helpers::infer_callee_return_shape(
        body,
        &param_consts_map,
        &functions,
        &mut std::collections::HashSet::new(),
    )
    .to_reg_types()?;

    let mut state = LiftState::new(params, param_consts, &functions);
    state.driver = Some(driver::LiftDriver::new());

    // Entry subprogram (id 0): same signal-in / witness-out walk as
    // the inlining path. Nested calls become `Call`s that reserve and
    // queue their callee subprograms.
    for stmt in body {
        state.lift_stmt(stmt)?;
        if state.halted {
            break;
        }
    }
    if !state.halted {
        return None;
    }
    let return_shape = state.return_shape;

    // Drain the reserved callees, lifting each body once into its own
    // subprogram. A callee discovered while lifting another callee is
    // queued and drained in turn.
    let mut drained = 0usize;
    while let Some(pending) = state.driver.as_mut()?.next_pending() {
        drained += 1;
        if drained > MAX_CALLEE_SUBPROGRAMS {
            return None;
        }
        let callee = state.functions.get(&pending.name).copied()?;
        if callee.params.len() != pending.param_sig.len() {
            return None;
        }
        let bindings: Vec<callee::CalleeParamBinding> = pending
            .param_sig
            .iter()
            .enumerate()
            .map(|(i, sig)| {
                let reg = i as artik::Reg;
                match sig {
                    driver::ParamSig::ScalarConst(v) => callee::CalleeParamBinding::Scalar {
                        reg,
                        const_val: Some(*v),
                    },
                    driver::ParamSig::ScalarRuntime => callee::CalleeParamBinding::Scalar {
                        reg,
                        const_val: None,
                    },
                    driver::ParamSig::Array1D(len) => {
                        callee::CalleeParamBinding::Array(ArrayShape::Flat1D {
                            handle: reg,
                            len: *len,
                        })
                    }
                    driver::ParamSig::Array2D(rows, cols) => {
                        callee::CalleeParamBinding::Array(ArrayShape::Flat2D {
                            handle: reg,
                            rows: *rows,
                            cols: *cols,
                        })
                    }
                }
            })
            .collect();

        let prev = state.builder.begin_subprogram(pending.func_id);
        let saved = state.begin_callee_body(callee, &bindings)?;
        for stmt in &callee.body.stmts {
            state.lift_stmt(stmt)?;
            if state.halted {
                break;
            }
        }
        // A callee subprogram must end in a `return` — otherwise it
        // would fall off the end without emitting `Return`.
        let returned = state.halted;
        state.end_callee_body(saved);
        state.builder.end_subprogram(prev);
        if !returned {
            return None;
        }
        // Recognized big-integer helpers get a native-intrinsic
        // annotation; the executor runs them natively when its guards
        // accept the inputs and interprets this body otherwise.
        if let Some(intrinsic) = intrinsics::recognize_intrinsic(
            &pending.name,
            callee,
            &pending.param_sig,
            state.functions,
        ) {
            state.builder.annotate_intrinsic(pending.func_id, intrinsic);
        }
    }

    let program = state.builder.finish().ok()?;
    let program_bytes = artik::bytecode::encode(&program);

    let anon_id = ctx.next_anon_id();
    let _ = span;
    let base = format!("__artik_{function_name}_{anon_id}_out");
    let (outputs, shape) = match return_shape {
        ReturnShape::Scalar => (vec![base], LiftedShape::Scalar),
        ReturnShape::Array(len) => {
            let names: Vec<String> = (0..len).map(|i| format!("{base}_{i}")).collect();
            (names, LiftedShape::Array(len))
        }
    };

    Some(LiftedWitnessCall {
        program_bytes,
        outputs,
        shape,
    })
}
