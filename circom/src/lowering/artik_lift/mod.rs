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
mod control;
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
/// Returns `None` for unsupported forms. The caller should fall back
/// to E212 in that case.
pub fn lift_function_to_artik(
    function_name: &str,
    params: &[(String, ParamShape)],
    body: &[Stmt],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<LiftedWitnessCall> {
    // Copy function refs out of `ctx` so the lift's nested-call
    // machinery can borrow them without holding `ctx` immutably for
    // the entire walk. The function definitions themselves live in
    // the AST and are stable for the duration of compilation.
    let functions: HashMap<String, &FunctionDef> = ctx
        .functions
        .iter()
        .map(|(&k, &v)| (k.to_string(), v))
        .collect();
    let mut state = LiftState::new(params, &functions);

    for stmt in body {
        state.lift_stmt(stmt)?;
        if state.halted {
            break;
        }
    }

    if !state.halted {
        // A well-formed function body must end with a `return`. If
        // none fired, treat as unsupported — we would otherwise emit
        // a program that never writes to the witness slot.
        return None;
    }

    let program = state.builder.finish().ok()?;
    let program_bytes = artik::bytecode::encode(&program);

    let anon_id = ctx.next_anon_id();
    let _ = span;
    let base = format!("__artik_{function_name}_{anon_id}_out");
    let (outputs, shape) = match state.return_shape {
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

/// Compile-time-known integer for loop variables. Circom integers can
/// in principle reach 254 bits, but loop bounds in witness functions
/// are consistently small (nbits, array lengths, round counts). i64
/// comfortably covers the entire circomlib corpus.
type ConstInt = i64;

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
    /// Array locals — each entry maps `name → (handle_reg, length)`.
    /// Writes via `arr[i] = expr` emit `StoreArr`; reads via
    /// `Expr::Index { object: Ident(arr), index }` emit `LoadArr`.
    arrays: HashMap<String, (Reg, u32)>,
    /// Set to `true` once a `return` has been lowered. The outer loop
    /// stops walking more statements and the program is finalized.
    halted: bool,
    /// What shape the `return` statement produced. Set on the
    /// handling of the `return`, read by the caller of
    /// `lift_function_to_artik` to decide how many witness slots the
    /// program exposes.
    return_shape: ReturnShape,
    /// Function table for inlining nested calls. The lift walks
    /// nested function bodies into the same builder, so a call like
    /// `return bar(x + 1);` becomes straight-line bytecode with
    /// bar's instructions interleaved into foo's.
    functions: &'f HashMap<String, &'f FunctionDef>,
    /// Non-zero while lifting a nested function body. Controls the
    /// `return` dispatch so nested returns capture a value into
    /// `nested_result` instead of emitting WriteWitness + Ret on the
    /// outer program.
    nested_depth: u32,
    /// Captures the return of a nested call. Inspected and cleared
    /// by `lift_nested_call`.
    nested_result: Option<NestedResult>,
    /// Witness slot id reserved for the function's scalar return value.
    /// Lazily populated on the first scalar `return` so multi-return
    /// shapes (e.g. early-exit `if (cond) return X;` followed by a
    /// later `return Y;`) all write to the same slot. `None` until the
    /// first scalar return; `Some` afterwards. Array returns continue
    /// to allocate per-element slots inline.
    output_slot: Option<u32>,
}

/// Value produced by a nested (inlined) function call. Arrays are
/// kept as handle + length so the caller can thread them through the
/// rest of the body identically to a `var arr[N];` local.
#[derive(Clone, Copy)]
enum NestedResult {
    Scalar(Reg),
    Array(Reg, u32),
}

impl<'f> LiftState<'f> {
    fn new(
        params: &[(String, ParamShape)],
        functions: &'f HashMap<String, &'f FunctionDef>,
    ) -> Self {
        let mut builder = ProgramBuilder::new(FieldFamily::BnLike256);
        let mut locals = HashMap::new();
        let mut arrays: HashMap<String, (Reg, u32)> = HashMap::new();

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
                    arrays.insert(name.clone(), (handle, *len));
                }
            }
        }
        Self {
            builder,
            locals,
            const_locals: HashMap::new(),
            arrays,
            halted: false,
            return_shape: ReturnShape::Scalar,
            functions,
            nested_depth: 0,
            nested_result: None,
            output_slot: None,
        }
    }
}
