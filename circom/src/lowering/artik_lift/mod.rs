//! Lift a circom function body into Artik witness bytecode.
//!
//! This is the Fase 2 replacement for the E212 "cannot be
//! circuit-inlined" diagnostic at [`expressions::calls`]: instead of
//! rejecting every function call with runtime-signal arguments and a
//! non-trivial body, we attempt to compile the body to Artik bytecode
//! and return a [`CircuitNode::WitnessCall`] to the caller.
//!
//! ## Supported surface
//!
//! The lift is intentionally narrow — enough to close common E212
//! patterns, while still rejecting shapes we cannot guarantee
//! correct. Currently supported:
//!
//! - **Statements**:
//!   - `var name [= expr];`, `name = expr;`
//!   - `return expr;`
//!   - `for (var i = <lit>; i < <lit>; i++) { body }` — unrolled at
//!     lift time; the loop variable becomes a compile-time constant
//!     inside the body. Also accepts `i <= N`, `i += 1`.
//! - **Expressions**: `Ident` (parameter → signal, local → register,
//!   loop var → compile-time constant), decimal / hex `Number`,
//!   `BinOp` of `Add / Sub / Mul / Div` over field-typed operands,
//!   `UnaryOp::Neg`. Bitwise ops
//!   (`BitAnd / BitOr / BitXor / ShiftL / ShiftR / BitNot`) lower by
//!   promoting operands to `IntW::U32`, applying the integer op, and
//!   promoting back to Field — sufficient for SHA-256-family witness
//!   functions whose internal state is u32.
//!
//! - **Control flow**:
//!   - `if (cond) { ... } else { ... }` — compile-time-foldable
//!     conditions pick a single branch; runtime conditions lower
//!     through a field-arithmetic mux
//!     (`cond_bool * then + (1 - cond_bool) * else`) provided both
//!     arms are pure-scalar (no array writes, no `return`).
//!
//! Anything else (non-constant loop bounds, tuple destructuring,
//! branches with side effects) returns `None` silently and the
//! caller falls back to E212.
//!
//! ## Non-goals
//!
//! - Soundness: the lift emits witness-hint-style outputs; the caller
//!   is responsible for pairing them with `===` downstream constraints
//!   if they want binding (same rule as circom's `<--`).
//! - Cross-backend: Artik bytecode is family-tagged `BnLike256` today.
//! - Non-literal loop bounds: loops over runtime-signal-dependent
//!   bounds need Jump / JumpIf driven by the executor, which the
//!   builder supports but the lift pass does not yet emit.

use std::collections::HashMap;

use artik::{ElemT, IntW, ProgramBuilder, Reg};
use diagnostics::Span;
use memory::FieldFamily;

use crate::ast::{BinOp, Expr, FunctionDef, PostfixOp, Stmt};
use crate::lowering::context::LoweringContext;

use self::helpers::{compound_to_binop, eval_const_expr};

mod bytecode;
mod control;
mod exprs;
mod helpers;

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

// ============================================================================
// LiftState — shared state for statement + expression lifting passes.
// ============================================================================

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
        }
    }

    // ── Statements ──────────────────────────────────────────────────

    fn lift_stmt(&mut self, stmt: &Stmt) -> Option<()> {
        if self.halted {
            return Some(());
        }
        match stmt {
            Stmt::VarDecl {
                names,
                dimensions,
                init,
                ..
            } => {
                // Tuple destructuring (`var (a, b) = ...`) is out of
                // scope — would need to unpack multiple return values.
                if names.len() != 1 {
                    return None;
                }
                let name = &names[0];

                // Array declaration: `var arr[N];` — allocate backing
                // storage once, at the declaration site. Multi-dim
                // arrays (`[N][M]`) are out of scope for this release.
                //
                // Two init shapes are honored:
                //   - no init (`var arr[N];`) — leave the backing
                //     store empty; the body must write to it before
                //     reading.
                //   - array literal (`var arr[N] = [e0, e1, ...];`) —
                //     lift each element into a field register at
                //     declaration time and emit a StoreArr. Needed by
                //     circomlib SHA-256 (`var k[64] = [0x..., ...]`
                //     inside `sha256K`).
                //
                // Non-literal initializers (e.g. `var a[n] = b;`
                // aliasing another array) still bail to the inliner.
                if !dimensions.is_empty() {
                    if dimensions.len() != 1 {
                        return None;
                    }
                    let size = eval_const_expr(&dimensions[0], &self.const_locals)?;
                    if !(0..=i64::from(u32::MAX)).contains(&size) {
                        return None;
                    }
                    let len = size as u32;
                    let handle = self.builder.alloc_array(len, ElemT::Field);

                    if let Some(init_expr) = init {
                        let Expr::ArrayLit { elements, .. } = init_expr else {
                            return None;
                        };
                        if usize::try_from(len).ok()? != elements.len() {
                            return None;
                        }
                        for (i, elem) in elements.iter().enumerate() {
                            let val_reg = self.lift_expr(elem)?;
                            let idx_reg = self.push_int_const(i as u64)?;
                            self.builder.store_arr(handle, idx_reg, val_reg);
                        }
                    }

                    self.arrays.insert(name.clone(), (handle, len));
                    return Some(());
                }

                let Some(expr) = init else {
                    // Uninitialized scalar `var x;` declares the name
                    // without a backing register — the body must
                    // assign to it via a Substitution before any use.
                    return Some(());
                };
                let r = self.lift_expr(expr)?;
                self.locals.insert(name.clone(), r);
                // An initialized var never lives in `const_locals` —
                // if an older iteration of the enclosing loop left a
                // compile-time entry, evict it so reads pick up the
                // new runtime register.
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::Substitution { target, value, .. } => {
                // Indexed assignment: `arr[i] = expr`. Supported when
                // `arr` is a declared array and `i` folds to a
                // compile-time index in bounds.
                if let Expr::Index { object, index, .. } = target {
                    let Expr::Ident { name, .. } = object.as_ref() else {
                        return None;
                    };
                    let (arr_reg, len) = self.arrays.get(name).copied()?;
                    let idx = eval_const_expr(index, &self.const_locals)?;
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    let idx_reg = self.push_int_const(idx as u64)?;
                    let val_reg = self.lift_expr(value)?;
                    self.builder.store_arr(arr_reg, idx_reg, val_reg);
                    return Some(());
                }
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                let r = self.lift_expr(value)?;
                self.locals.insert(name.clone(), r);
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::CompoundAssign {
                target, op, value, ..
            } => {
                // Compound assignment: `x += expr`, `x *= expr`, etc.
                // Rewrite as `x = x <op> expr` and route through the
                // normal expression lift. If `x` is a compile-time
                // loop variable and `expr` folds to a constant, we
                // prefer to mutate `const_locals` so downstream
                // lookups keep folding — otherwise the variable
                // transitions to a runtime register.
                //
                // Indexed target (`arr[i] += expr`): supported when
                // `arr` is a declared array. Required by circomlib
                // SHA-256's `H[i] += hin[i*32+j] << j` and
                // `w[i] += inp[i*32+31-j] << j` accumulators.
                let binop = compound_to_binop(*op)?;
                if let Expr::Index { object, index, .. } = target {
                    let Expr::Ident { name, .. } = object.as_ref() else {
                        return None;
                    };
                    let (arr_reg, len) = self.arrays.get(name).copied()?;
                    let idx = eval_const_expr(index, &self.const_locals)?;
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    let idx_reg = self.push_int_const(idx as u64)?;
                    let cur = self.builder.load_arr(arr_reg, idx_reg);
                    let rhs_reg = self.lift_expr(value)?;
                    let new_val = self.apply_field_binop(binop, cur, rhs_reg)?;
                    self.builder.store_arr(arr_reg, idx_reg, new_val);
                    return Some(());
                }
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                if let Some(current) = self.const_locals.get(name).copied() {
                    if let Some(rhs_const) = eval_const_expr(value, &self.const_locals) {
                        let folded = match binop {
                            BinOp::Add => current.checked_add(rhs_const),
                            BinOp::Sub => current.checked_sub(rhs_const),
                            BinOp::Mul => current.checked_mul(rhs_const),
                            _ => None,
                        };
                        if let Some(v) = folded {
                            self.const_locals.insert(name.clone(), v);
                            return Some(());
                        }
                    }
                }
                let lhs_reg = self.lookup_ident(name)?;
                let rhs_reg = self.lift_expr(value)?;
                let r = self.apply_field_binop(binop, lhs_reg, rhs_reg)?;
                self.locals.insert(name.clone(), r);
                self.const_locals.remove(name);
                Some(())
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
                ..
            } => self.lift_for(init, condition, step, &body.stmts),
            Stmt::IfElse {
                condition,
                then_body,
                else_body,
                ..
            } => self.lift_if_else(condition, then_body, else_body.as_ref()),
            Stmt::Return { value, .. } => {
                // Array-return: `return <local_array>;` — for the
                // outer function, expose each element as its own
                // witness slot so the caller can re-bundle them into
                // a `CircuitNode::LetArray`. For a nested inlined
                // call, hand the array handle back to the caller's
                // lift_expr via `nested_result` — no slot allocation.
                if let Expr::Ident { name, .. } = value {
                    if let Some(&(arr_reg, len)) = self.arrays.get(name) {
                        if self.nested_depth > 0 {
                            self.nested_result = Some(NestedResult::Array(arr_reg, len));
                            self.halted = true;
                            return Some(());
                        }
                        for i in 0..len {
                            let slot = self.builder.alloc_witness_slot();
                            let idx_reg = self.push_int_const(i as u64)?;
                            let val_reg = self.builder.load_arr(arr_reg, idx_reg);
                            self.builder.write_witness(slot, val_reg);
                        }
                        self.builder.ret();
                        self.halted = true;
                        self.return_shape = ReturnShape::Array(len);
                        return Some(());
                    }
                }

                // Scalar return.
                let r = self.lift_expr(value)?;
                if self.nested_depth > 0 {
                    self.nested_result = Some(NestedResult::Scalar(r));
                    self.halted = true;
                    return Some(());
                }
                let slot = self.builder.alloc_witness_slot();
                self.builder.write_witness(slot, r);
                self.builder.ret();
                self.halted = true;
                self.return_shape = ReturnShape::Scalar;
                Some(())
            }
            Stmt::Expr { expr, .. } => {
                // Bare expression statement. Only supported when it's
                // a postfix/prefix increment/decrement on a loop var —
                // the actual value is discarded; the side effect
                // mutates the const_locals entry. This is what lets
                // `for (; ; i++)` round-trip cleanly when the loop is
                // unrolled via `lift_for`.
                self.apply_side_effect(expr)
            }
            _ => None,
        }
    }

    /// Mutate `const_locals` if `expr` is a supported side-effect form
    /// (postfix / prefix `++` or `--` on a compile-time-tracked var).
    /// Returns `None` for anything else, which falls back to E212.
    fn apply_side_effect(&mut self, expr: &Expr) -> Option<()> {
        let (op, operand) = match expr {
            Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => {
                (op, operand)
            }
            _ => return None,
        };
        let Expr::Ident { name, .. } = operand.as_ref() else {
            return None;
        };
        // Only compile-time-tracked vars support ++/--: a runtime
        // `i++` would require loading, adding 1, storing, which the
        // lift can support later but does not today.
        let current = self.const_locals.get(name).copied()?;
        let next = match op {
            PostfixOp::Increment => current.checked_add(1)?,
            PostfixOp::Decrement => current.checked_sub(1)?,
        };
        self.const_locals.insert(name.clone(), next);
        Some(())
    }

}
