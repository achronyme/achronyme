//! Lift a circom function body into Artik witness bytecode.
//!
//! The lift returns a [`LiftedWitnessCall`] that the caller emits as
//! [`CircuitNode::WitnessCall`] instead of failing with the
//! "cannot be circuit-inlined" E212 diagnostic at
//! [`expressions::calls`] for runtime-signal arguments. Function calls
//! with runtime-signal arguments and a non-trivial body are compiled
//! to Artik bytecode that runs at witness-generation time.
//!
//! ## Submodules
//!
//! - [`stmts`] — [`LiftState::lift_stmt`] and the postfix/prefix side-effect
//!   helper.
//! - [`control`] — `for` unrolling and `if / else` lowering (compile-time
//!   fold + runtime mux).
//! - [`exprs`] — expression dispatch, identifier lookup, nested-function
//!   inlining.
//! - [`bytecode`] — Artik builder primitives (binops, demote/promote
//!   between field and `IntW::U32`, constant-pool emitters).
//! - [`helpers`] — pure free functions used across submodules
//!   (compile-time eval, mux-compatibility shape checks, compound-op map).
//!
//! ## Supported surface
//!
//! The lift is intentionally narrow — enough to close common E212
//! patterns, while still rejecting shapes we cannot guarantee correct.
//! Currently supported:
//!
//! - **Statements**: `var name [= expr];`, `name = expr;`, `return expr;`,
//!   `for (...)` over literal bounds (unrolled at lift time), `if / else`
//!   with compile-time-foldable or pure-scalar runtime conditions.
//! - **Expressions**: `Ident`, decimal / hex `Number`, `BinOp`
//!   (`Add / Sub / Mul / Div`), `UnaryOp::Neg`. Bitwise ops
//!   (`BitAnd / BitOr / BitXor / ShiftL / ShiftR / BitNot`) lower by
//!   promoting to `IntW::U32`, applying the integer op, and promoting
//!   back to Field — sufficient for SHA-256-family witness functions.
//!
//! Anything else returns `None` silently and the caller falls back to
//! E212.
//!
//! ## Non-goals
//!
//! - Soundness: the lift emits witness-hint-style outputs; the caller
//!   pairs them with `===` downstream constraints if they want binding.
//! - Cross-backend: Artik bytecode is family-tagged `BnLike256` today.

use std::collections::HashMap;

use artik::{ElemT, IntW, ProgramBuilder, Reg};
use diagnostics::Span;
use memory::FieldFamily;

use crate::ast::{FunctionDef, Stmt};
use crate::lowering::context::LoweringContext;

mod big_eval;
mod bytecode;
mod callee;
mod control;
mod driver;
mod exprs;
mod helpers;
mod stmts;

/// Result of a successful lift: the serialized Artik program + the
/// names of the witness slots the caller should bind to.
pub struct LiftedWitnessCall {
    pub program_bytes: Vec<u8>,
    pub outputs: Vec<String>,
    /// Shape the caller should expose. `Scalar` → a single binding
    /// substitutes for the call site's returned CircuitExpr;
    /// `Array(len)` → the lift wrote one slot per element and the
    /// caller needs to re-bundle them into a `LetArray` before the
    /// usage site can read the function's result as an array.
    pub shape: LiftedShape,
}

/// Output shape the lift produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftedShape {
    Scalar,
    Array(u32),
    /// Row-major 2D output. The caller emits one flat `LetArray` of
    /// `rows*cols` elements; the destination's var-decl handler seeds
    /// `env.strides` from the syntactic `[R][C]` dimensions so
    /// subsequent `arr[r][c]` accesses linearise as `r * cols + c`.
    Array2D {
        rows: u32,
        cols: u32,
    },
}

/// Shape of a function parameter at the call site. The lift needs
/// to know this at binding time because an array parameter consumes
/// N input signals (one per element, laid out in index order) while
/// a scalar consumes one. Circom infers the shape from the argument
/// passed at the call site, not from the function's declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamShape {
    Scalar,
    /// 1D array with the given element count.
    Array(u32),
}

/// Attempt to compile `body` — the statements of a circom function —
/// into an Artik program. Parameters are provided as signal ids in
/// the order they appear in the function's `params` list; the caller
/// will bind each `arg` expression to the corresponding signal slot
/// at prove time.
///
/// Nested circom function calls are lifted as real Artik subprogram
/// `Call`s — one subprogram per callee, registered once per parameter
/// signature — not inlined into the caller's flat program.
///
/// Returns `None` for unsupported forms. The caller should fall back
/// to E212 in that case.

// THROWAWAY measurement instrumentation — remove before merge.
// Appends to the file named by ARTIK_SUBPROG_TRACE_FILE so traces
// survive cargo's per-test stdout/stderr capture (which is discarded
// for passing tests). O_APPEND short-line writes are atomic enough
// across the parallel test threads for this measurement.
pub(super) fn sp_trace(what: &str) {
    use std::io::Write;
    if let Ok(path) = std::env::var("ARTIK_SUBPROG_TRACE_FILE") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "[SP-TRACE] {what}");
        }
    }
}

pub fn lift_function_to_artik(
    function_name: &str,
    params: &[(String, ParamShape)],
    param_consts: &[Option<ConstInt>],
    body: &[Stmt],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<LiftedWitnessCall> {
    if let Some(lifted) =
        try_lift_via_subprograms(function_name, params, param_consts, body, ctx, span)
    {
        sp_trace(&format!("SUCCESS fn={function_name}"));
        return Some(lifted);
    }
    sp_trace(&format!("DECLINE-TOPLEVEL fn={function_name}"));
    None
}

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
fn try_lift_via_subprograms(
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
    if helpers::compute_dim_signature(body, &param_consts_map).is_none() {
        sp_trace(&format!(
            "decline reason=entry_runtime_dim fn={function_name}"
        ));
        return None;
    }
    // Built before the return-shape gate: a `return f(..)` forwarded
    // return resolves to f's shape, which the classifier reads from
    // this registry.
    let functions: HashMap<String, &FunctionDef> = ctx
        .functions
        .iter()
        .map(|(&k, &v)| (k.to_string(), v))
        .collect();
    if helpers::infer_callee_return_shape(
        body,
        &param_consts_map,
        &functions,
        &mut std::collections::HashSet::new(),
    )
    .to_reg_types()
    .is_none()
    {
        sp_trace(&format!(
            "decline reason=entry_return_shape fn={function_name}"
        ));
        return None;
    }

    let mut state = LiftState::new(params, param_consts, &functions);
    state.driver = Some(driver::LiftDriver::new());

    // Entry subprogram (id 0): same signal-in / witness-out walk as
    // the inlining path. Nested calls become `Call`s that reserve and
    // queue their callee subprograms.
    for stmt in body {
        if state.lift_stmt(stmt).is_none() {
            sp_trace(&format!(
                "decline reason=entry_lift_stmt fn={function_name}"
            ));
            return None;
        }
        if state.halted {
            break;
        }
    }
    if !state.halted {
        sp_trace(&format!(
            "decline reason=entry_no_return fn={function_name}"
        ));
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
            sp_trace(&format!("decline reason=max_callees fn={function_name}"));
            return None;
        }
        let callee = state.functions.get(&pending.name).copied()?;
        if callee.params.len() != pending.param_sig.len() {
            sp_trace(&format!(
                "decline reason=callee_arity fn={function_name} callee={}",
                pending.name
            ));
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
            if state.lift_stmt(stmt).is_none() {
                sp_trace(&format!(
                    "decline reason=callee_lift_stmt fn={function_name} callee={}",
                    pending.name
                ));
                return None;
            }
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
            sp_trace(&format!(
                "decline reason=callee_no_return fn={function_name} callee={}",
                pending.name
            ));
            return None;
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

/// Internal bookkeeping — what the function returned. Populated by
/// `lift_stmt` when it sees the `return` statement; consumed by the
/// top-level `lift_function_to_artik` to pick between single-slot
/// and multi-slot output naming.
#[derive(Clone, Copy)]
enum ReturnShape {
    Scalar,
    Array(u32),
}

/// Shape of a local array allocation: either a flat 1D field array of
/// `len` cells, or a 2D field array of `rows × cols` flattened with
/// row-major stride. The Artik VM has no native 2D primitive; we
/// flatten at lift time and emit the index computation `i * cols + j`
/// before each LoadArr / StoreArr.
#[derive(Clone, Copy)]
pub(super) enum ArrayShape {
    Flat1D { handle: Reg, len: u32 },
    Flat2D { handle: Reg, rows: u32, cols: u32 },
}

impl ArrayShape {
    pub(super) fn handle(self) -> Reg {
        match self {
            Self::Flat1D { handle, .. } => handle,
            Self::Flat2D { handle, .. } => handle,
        }
    }

    /// Total flattened length — `len` for 1D, `rows * cols` for 2D.
    pub(super) fn total_len(self) -> u32 {
        match self {
            Self::Flat1D { len, .. } => len,
            Self::Flat2D { rows, cols, .. } => rows.saturating_mul(cols),
        }
    }

    /// View as a 1D shape if applicable. 2D shapes return None — the
    /// caller has to handle the multi-index path explicitly.
    pub(super) fn as_1d(self) -> Option<(Reg, u32)> {
        match self {
            Self::Flat1D { handle, len } => Some((handle, len)),
            Self::Flat2D { .. } => None,
        }
    }
}

/// Compile-time-known integer for loop variables. Circom integers can
/// in principle reach 254 bits, but loop bounds in witness functions
/// are consistently small (nbits, array lengths, round counts). i64
/// comfortably covers the entire circomlib corpus.
pub type ConstInt = i64;

struct LiftState<'f> {
    builder: ProgramBuilder,
    /// Runtime-valued locals — each name holds a register that carries
    /// its current value. Mutable: a reassignment overwrites the
    /// stored register.
    locals: HashMap<String, Reg>,
    /// Compile-time-known locals — loop variables during unrolling,
    /// plus any purely constant vars we recognize. Takes precedence
    /// over `locals` when an identifier is looked up.
    const_locals: HashMap<String, ConstInt>,
    /// Array locals — each entry maps `name → ArrayShape`. 1D arrays
    /// route through `LoadArr` / `StoreArr` directly; 2D arrays
    /// flatten the row-major index `i * cols + j` at lift time before
    /// dispatching to the same opcodes.
    arrays: HashMap<String, ArrayShape>,
    /// Set to `true` once a `return` has been lowered. The outer loop
    /// stops walking more statements and the program is finalized.
    halted: bool,
    /// What shape the `return` statement produced. Set on the
    /// handling of the `return`, read by the caller of
    /// `lift_function_to_artik` to decide how many witness slots the
    /// program exposes.
    return_shape: ReturnShape,
    /// Function table for resolving nested calls. A nested call is
    /// reserved as a callee subprogram and invoked with a real Artik
    /// `Call`; its body is looked up here.
    functions: &'f HashMap<String, &'f FunctionDef>,
    /// Witness slot id reserved for the function's scalar return value.
    /// Lazily populated on the first scalar `return` so multi-return
    /// shapes (e.g. early-exit `if (cond) return X;` followed by a
    /// later `return Y;`) all write to the same slot. `None` until the
    /// first scalar return; `Some` afterwards.
    output_slot: Option<u32>,
    /// Witness slots reserved for the function's array return value.
    /// Functions with multiple array-returning paths (e.g.
    /// `mod_inv`'s `if (isZero) return ret;` early-exit followed by a
    /// later `return out;`) must reuse the same slot range across all
    /// returns — otherwise each path allocates a fresh range and the
    /// caller sees the wrong count. Lazily populated on the first
    /// array return; subsequent returns require a matching length.
    output_array_slots: Option<Vec<u32>>,
    /// Arrays that have been pre-allocated by an enclosing
    /// `lift_while`. When the body's `VarDecl` re-encounters one of
    /// these names, it must skip the `AllocArray` — otherwise the
    /// runtime loop allocates a fresh array on every iteration and
    /// the heap budget explodes. The map records the *declared*
    /// shape so the skip check survives later rebinds (a
    /// `temp = prod(...)` rebind shrinks the live shape from 200 to
    /// 100, but the next iter's `var temp[200]` declaration must
    /// still match the originally-hoisted 200). Cleared when the
    /// enclosing `lift_while` returns.
    hoisted_arrays: std::collections::HashMap<String, ArrayShape>,
    /// Callee registry, present only on the subprogram-lift path.
    /// `None` on the inlining path — every method that consults it
    /// then takes the existing branch, so the inlining path is
    /// byte-identical. `Some` enables real `Call`/subprogram emission:
    /// nested calls reserve callee subprograms and the callee bodies
    /// are drained from it after the entry body is lifted.
    driver: Option<driver::LiftDriver>,
}

/// Value produced by a nested (inlined) function call. Arrays are
/// kept as handle + length so the caller can thread them through the
/// rest of the body identically to a `var arr[N];` local. 2D arrays
/// preserve their `(rows, cols)` shape so the caller can rebind them
/// to a `Flat2D` slot without losing the row-major stride.
#[derive(Clone, Copy)]
enum NestedResult {
    Scalar(Reg),
    Array(Reg, u32),
    Array2D(Reg, u32, u32),
}

impl<'f> LiftState<'f> {
    fn new(
        params: &[(String, ParamShape)],
        param_consts: &[Option<ConstInt>],
        functions: &'f HashMap<String, &'f FunctionDef>,
    ) -> Self {
        let mut builder = ProgramBuilder::new(FieldFamily::BnLike256);
        let mut locals = HashMap::new();
        let mut const_locals: HashMap<String, ConstInt> = HashMap::new();
        let mut arrays: HashMap<String, ArrayShape> = HashMap::new();

        // Bind any compile-time-known scalar args into the callee's
        // const_locals so patterns like `1 << n` fold at lift time and
        // dispatch to FShr / FAnd instead of falling through to a
        // runtime IntW::U32 demote (or, worse, a runtime FIDiv / FIRem
        // when both operands are field cells).
        for (i, (name, shape)) in params.iter().enumerate() {
            if matches!(shape, ParamShape::Scalar) {
                if let Some(Some(v)) = param_consts.get(i) {
                    const_locals.insert(name.clone(), *v);
                }
            }
        }

        // Materialize a small index cache so the StoreArr sequence
        // below doesn't emit a fresh PushConst+IntFromField pair for
        // each (already-known) index — the validator still accepts it
        // either way, but the body stays cleaner for disassembly.
        let mut index_cache: HashMap<u32, Reg> = HashMap::new();

        for (name, shape) in params {
            match shape {
                ParamShape::Scalar => {
                    let sig = builder.alloc_signal();
                    let reg = builder.read_signal(sig);
                    locals.insert(name.clone(), reg);
                }
                ParamShape::Array(len) => {
                    // Allocate backing storage + read each element
                    // from its own dedicated input signal. The call
                    // site is responsible for supplying exactly `len`
                    // input_signals in the WitnessCall, laid out in
                    // index order — the per-param offset is implicit
                    // in the signal allocation order here.
                    let handle = builder.alloc_array(*len, ElemT::Field);
                    for i in 0..*len {
                        let sig = builder.alloc_signal();
                        let elem_reg = builder.read_signal(sig);
                        let idx_reg = *index_cache.entry(i).or_insert_with(|| {
                            let zero_bytes: Vec<u8> = (i as u128).to_le_bytes().to_vec();
                            let trimmed: Vec<u8> = {
                                let mut b = zero_bytes;
                                while b.last() == Some(&0) && b.len() > 1 {
                                    b.pop();
                                }
                                b
                            };
                            let cid = builder.intern_const(trimmed);
                            let field_reg = builder.push_const(cid);
                            builder.int_from_field(IntW::U32, field_reg)
                        });
                        builder.store_arr(handle, idx_reg, elem_reg);
                    }
                    arrays.insert(name.clone(), ArrayShape::Flat1D { handle, len: *len });
                }
            }
        }
        Self {
            builder,
            locals,
            const_locals,
            arrays,
            halted: false,
            return_shape: ReturnShape::Scalar,
            functions,
            output_slot: None,
            output_array_slots: None,
            hoisted_arrays: std::collections::HashMap::new(),
            driver: None,
        }
    }
}
