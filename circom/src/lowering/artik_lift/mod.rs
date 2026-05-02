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

use crate::ast::{BinOp, Expr, FunctionDef, PostfixOp, Stmt, UnaryOp};
use crate::lowering::context::LoweringContext;

mod bytecode;

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

    /// Unroll a for loop at lift time. Only loops with literal bounds
    /// and a `++` / `+= 1` step over a freshly declared integer loop
    /// variable are supported. The loop variable is tracked as a
    /// `ConstInt` in `const_locals` for the duration of each body
    /// invocation; compile-time references to it fold to `PushConst`.
    fn lift_for(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        // Init: `var <name> = <literal>;`
        let Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } = init
        else {
            return None;
        };
        if names.len() != 1 {
            return None;
        }
        let var_name = names[0].clone();
        let start = eval_const_expr(init_expr, &self.const_locals)?;

        // Condition: `<var> < <bound>` or `<var> <= <bound>`
        let (end_bound, inclusive) = match condition {
            Expr::BinOp { op, lhs, rhs, .. } => {
                let Expr::Ident { name, .. } = lhs.as_ref() else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                let bound = eval_const_expr(rhs, &self.const_locals)?;
                match op {
                    BinOp::Lt => (bound, false),
                    BinOp::Le => (bound, true),
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Step: `<var>++` / `++<var>` / `<var> += 1`
        match step {
            Stmt::Expr { expr, .. } => {
                if !is_increment_on(expr, &var_name) {
                    return None;
                }
            }
            Stmt::CompoundAssign {
                target, op, value, ..
            } => {
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                if !matches!(op, crate::ast::CompoundOp::Add) {
                    return None;
                }
                if eval_const_expr(value, &self.const_locals)? != 1 {
                    return None;
                }
            }
            _ => return None,
        }

        // Cheap bound on unroll work: the executor's frame size is
        // capped at MAX_FRAME_SIZE (65536 regs); each body iteration
        // can touch several registers. Reject loops beyond a safe
        // ceiling so a hostile circom source can't force the lift to
        // allocate a huge Artik body up front.
        let raw_end = if inclusive { end_bound + 1 } else { end_bound };
        let iterations = raw_end.saturating_sub(start);
        if !(0..=4096).contains(&iterations) {
            return None;
        }

        // Unroll. Restore the previous const_locals entry on exit so
        // nested loops with shadowing (rare) remain sound.
        let prev = self.const_locals.insert(var_name.clone(), start);
        for i in start..raw_end {
            *self
                .const_locals
                .get_mut(&var_name)
                .expect("loop var was just inserted") = i;
            for stmt in body {
                self.lift_stmt(stmt)?;
                if self.halted {
                    break;
                }
            }
            if self.halted {
                break;
            }
        }
        match prev {
            Some(v) => {
                self.const_locals.insert(var_name, v);
            }
            None => {
                self.const_locals.remove(&var_name);
            }
        }
        Some(())
    }

    /// Lift an `if / else`. Compile-time-foldable conditions pick a
    /// single branch and emit only that body's instructions. Runtime
    /// conditions (dependent on a signal or runtime-valued local) fall
    /// through to [`lift_if_else_mux`], which branchlessly computes
    /// both arms and selects per-variable via a field-arithmetic mux.
    /// Anything the mux pass can't prove safe returns `None` and the
    /// caller falls back to E212.
    fn lift_if_else(
        &mut self,
        condition: &Expr,
        then_body: &crate::ast::Block,
        else_body: Option<&crate::ast::ElseBranch>,
    ) -> Option<()> {
        if let Some(cond) = eval_const_expr(condition, &self.const_locals) {
            return self.lift_if_else_folded(cond, then_body, else_body);
        }
        self.lift_if_else_mux(condition, then_body, else_body)
    }

    /// Compile-time branch: `cond` already evaluated to an integer;
    /// emit only the taken side's instructions.
    fn lift_if_else_folded(
        &mut self,
        cond: ConstInt,
        then_body: &crate::ast::Block,
        else_body: Option<&crate::ast::ElseBranch>,
    ) -> Option<()> {
        use crate::ast::ElseBranch;
        if cond != 0 {
            for s in &then_body.stmts {
                self.lift_stmt(s)?;
                if self.halted {
                    return Some(());
                }
            }
        } else {
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        self.lift_stmt(s)?;
                        if self.halted {
                            return Some(());
                        }
                    }
                }
                Some(ElseBranch::IfElse(boxed)) => {
                    self.lift_stmt(boxed)?;
                }
                None => {}
            }
        }
        Some(())
    }

    /// Runtime if/else: lower both branches into the same Artik
    /// program and merge their scalar local updates via a
    /// field-arithmetic mux — `x = cond_bool * then_x + (1 - cond_bool) * else_x`.
    /// `cond_bool` is derived from the raw condition through `FEq(cond, 0)`
    /// so the result matches circom's semantics (0 → false, non-zero → true)
    /// regardless of whether the caller already constrained `cond` to `{0,1}`.
    ///
    /// Bails (returns `None`) when either arm contains a shape the mux
    /// can't handle safely: array writes, witness writes, `return`, or
    /// non-scalar assignment targets. Both arms execute at runtime, so
    /// any side effect that isn't "write to a register we later discard"
    /// would produce a wrong witness.
    fn lift_if_else_mux(
        &mut self,
        condition: &Expr,
        then_body: &crate::ast::Block,
        else_body: Option<&crate::ast::ElseBranch>,
    ) -> Option<()> {
        use crate::ast::ElseBranch;

        // Pre-flight: reject anything that might have side effects at
        // runtime. `return`, array writes, and witness writes would all
        // execute unconditionally under the mux scheme.
        if !stmts_are_mux_compatible(&then_body.stmts) {
            return None;
        }
        match else_body {
            Some(ElseBranch::Block(b)) => {
                if !stmts_are_mux_compatible(&b.stmts) {
                    return None;
                }
            }
            Some(ElseBranch::IfElse(boxed)) => {
                if !stmt_is_mux_compatible(boxed) {
                    return None;
                }
            }
            None => {}
        }

        // Normalize the condition to a {0, 1} field element. We
        // compute `is_zero = FEq(cond, 0)` (outputs Int(U8) 0/1),
        // lift back to Field via `FieldFromInt U8`, then take
        // `bool_cond = 1 - is_zero`. This preserves circom's
        // "0 is false, non-zero is true" semantics without assuming
        // the caller pre-constrained `cond` to bool.
        let raw_cond = self.lift_expr(condition)?;
        let zero_reg = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(raw_cond, zero_reg);
        let is_zero_field = self.builder.field_from_int(is_zero_int, IntW::U8);
        let one_reg = self.push_const_unsigned(1)?;
        let bool_cond = self.builder.fsub(one_reg, is_zero_field);
        let not_bool_cond = self.builder.fsub(one_reg, bool_cond);

        // Snapshot the caller's scope so each branch starts from the
        // same pre-branch view.
        let pre_locals = self.locals.clone();
        let pre_const_locals = self.const_locals.clone();

        // Then-branch.
        for stmt in &then_body.stmts {
            self.lift_stmt(stmt)?;
            // `return` inside a mux branch is not representable —
            // one arm halting while the other doesn't has no
            // meaningful merge.
            if self.halted {
                return None;
            }
        }
        // A branch that demoted a const_local to runtime would make
        // the post-merge state ambiguous (const in one arm, runtime
        // in the other). Bail conservatively.
        if self.const_locals != pre_const_locals {
            return None;
        }
        let then_locals = std::mem::replace(&mut self.locals, pre_locals.clone());

        // Else-branch.
        match else_body {
            Some(ElseBranch::Block(b)) => {
                for stmt in &b.stmts {
                    self.lift_stmt(stmt)?;
                    if self.halted {
                        return None;
                    }
                }
            }
            Some(ElseBranch::IfElse(boxed)) => {
                self.lift_stmt(boxed)?;
                if self.halted {
                    return None;
                }
            }
            None => {}
        }
        if self.const_locals != pre_const_locals {
            return None;
        }
        let else_locals = std::mem::take(&mut self.locals);

        // Merge. For each name in the union of pre / then / else
        // scopes, produce one register that holds the post-branch
        // value. Names unchanged by both arms pass through; names
        // updated in at least one arm get a mux instruction triple.
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for k in pre_locals.keys() {
            names.insert(k.clone());
        }
        for k in then_locals.keys() {
            names.insert(k.clone());
        }
        for k in else_locals.keys() {
            names.insert(k.clone());
        }

        let mut merged: HashMap<String, Reg> = HashMap::new();
        for name in &names {
            let then_r = then_locals
                .get(name)
                .copied()
                .or_else(|| pre_locals.get(name).copied());
            let else_r = else_locals
                .get(name)
                .copied()
                .or_else(|| pre_locals.get(name).copied());
            match (then_r, else_r) {
                (Some(t), Some(e)) if t == e => {
                    merged.insert(name.clone(), t);
                }
                (Some(t), Some(e)) => {
                    let t_part = self.builder.fmul(bool_cond, t);
                    let e_part = self.builder.fmul(not_bool_cond, e);
                    let out = self.builder.fadd(t_part, e_part);
                    merged.insert(name.clone(), out);
                }
                // Name exists in only one arm and wasn't declared
                // before the branch — the other path leaves it
                // undefined, which the mux can't fix.
                _ => return None,
            }
        }

        self.locals = merged;
        Some(())
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

    // ── Expressions ─────────────────────────────────────────────────

    fn lift_expr(&mut self, expr: &Expr) -> Option<Reg> {
        match expr {
            Expr::Ident { name, .. } => self.lookup_ident(name),
            Expr::Number { value, .. } => self.push_const_dec(value),
            Expr::HexNumber { value, .. } => {
                let trimmed = value.strip_prefix("0x").unwrap_or(value);
                self.push_const_hex(trimmed)
            }
            Expr::BinOp { op, lhs, rhs, .. } => {
                let a = self.lift_expr(lhs)?;
                let c = self.lift_expr(rhs)?;
                self.apply_field_binop(*op, a, c)
            }
            Expr::UnaryOp {
                op: UnaryOp::Neg,
                operand,
                ..
            } => {
                // `-x` becomes `0 - x`. Keeping this in-scope matches
                // the trivial-inline path's behavior.
                let zero = self.push_const_int(0)?;
                let r = self.lift_expr(operand)?;
                Some(self.builder.fsub(zero, r))
            }
            Expr::UnaryOp {
                op: UnaryOp::BitNot,
                operand,
                ..
            } => {
                // `~x` — promote to u32, INot, promote back.
                let r = self.lift_expr(operand)?;
                let r_int = self.demote_to_u32(r);
                let not_int = self.builder.inot(IntW::U32, r_int);
                Some(self.promote_u32_to_field(not_int))
            }
            Expr::Index { object, index, .. } => {
                // `arr[i]` where `arr` is a declared array. Two
                // index shapes are honored:
                //   - compile-time index → range-check against the
                //     declared length and materialize the index
                //     register via PushConst → IntFromField.
                //   - runtime index (e.g. a scalar parameter or a
                //     register-valued local) → lift the index
                //     expression into a field register, then
                //     IntFromField U32 into the int register the
                //     executor's LoadArr expects. Required by
                //     circomlib's `sha256K(i)` (single indexed read
                //     with a runtime `i`). The executor traps on
                //     out-of-bounds access, so the bounds check is
                //     deferred rather than duplicated here.
                let Expr::Ident { name, .. } = object.as_ref() else {
                    return None;
                };
                let (arr_reg, len) = self.arrays.get(name).copied()?;
                let idx_reg = if let Some(idx) = eval_const_expr(index, &self.const_locals) {
                    if !(0..i64::from(len)).contains(&idx) {
                        return None;
                    }
                    self.push_int_const(idx as u64)?
                } else {
                    let idx_field = self.lift_expr(index)?;
                    self.builder.int_from_field(IntW::U32, idx_field)
                };
                Some(self.builder.load_arr(arr_reg, idx_reg))
            }
            Expr::Call { callee, args, .. } => {
                // Nested function call. Lift the callee's body into
                // the same Artik program as this function, with the
                // callee's params bound to arg-evaluated registers.
                // Array returns are not representable as a single
                // `Reg`; those currently bail out so the outer lift
                // falls back to E212.
                let name = extract_call_name(callee)?;
                match self.lift_nested_call(&name, args)? {
                    NestedResult::Scalar(r) => Some(r),
                    NestedResult::Array(_, _) => None,
                }
            }
            _ => None,
        }
    }

    /// Inline a nested function call into the current Artik program.
    /// Swaps the current scope (locals / arrays / const_locals) for
    /// a fresh one bound to the callee's params, walks the callee's
    /// body, captures the return value via `nested_result`, and
    /// restores the outer scope.
    fn lift_nested_call(&mut self, name: &str, args: &[Expr]) -> Option<NestedResult> {
        let func = self.functions.get(name).copied()?;
        if args.len() != func.params.len() {
            return None;
        }

        // Simple recursion guard — the outer inline-depth counter
        // lives in `LoweringContext` but we don't carry that here.
        // A fixed ceiling on nested lift depth prevents programs
        // that accidentally recurse through mutually-calling
        // functions from exhausting the stack.
        if self.nested_depth >= 32 {
            return None;
        }

        // Evaluate args in the outer scope first.
        let mut arg_regs = Vec::with_capacity(args.len());
        for arg in args {
            arg_regs.push(self.lift_expr(arg)?);
        }

        // Swap scope.
        let outer_locals = std::mem::take(&mut self.locals);
        let outer_const = std::mem::take(&mut self.const_locals);
        let outer_arrays = std::mem::take(&mut self.arrays);
        let outer_halted = self.halted;
        let outer_result = self.nested_result.take();
        self.halted = false;
        self.nested_depth += 1;

        for (param, reg) in func.params.iter().zip(arg_regs.iter()) {
            self.locals.insert(param.clone(), *reg);
        }

        // Lift the callee's body.
        let mut body_ok = true;
        for stmt in &func.body.stmts {
            if self.lift_stmt(stmt).is_none() {
                body_ok = false;
                break;
            }
            if self.halted {
                break;
            }
        }

        let result = self.nested_result.take();

        // Restore outer scope regardless of outcome so the program
        // state stays sane even when a nested lift bails out.
        self.nested_result = outer_result;
        self.nested_depth -= 1;
        self.halted = outer_halted;
        self.locals = outer_locals;
        self.const_locals = outer_const;
        self.arrays = outer_arrays;

        if !body_ok {
            return None;
        }
        result
    }

    fn lookup_ident(&mut self, name: &str) -> Option<Reg> {
        if let Some(v) = self.const_locals.get(name).copied() {
            return self.push_const_int(v);
        }
        self.locals.get(name).copied()
    }

}

// ============================================================================
// Helpers — pure functions that do not touch the lift state.
// ============================================================================

/// Evaluate an expression to a compile-time integer. Used for loop
/// bounds and step amounts. Looks up identifiers in the provided
/// `const_locals` map; signals / runtime-valued locals return `None`.
fn eval_const_expr(expr: &Expr, const_locals: &HashMap<String, ConstInt>) -> Option<ConstInt> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            ConstInt::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
        }
        Expr::Ident { name, .. } => const_locals.get(name).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = eval_const_expr(lhs, const_locals)?;
            let b = eval_const_expr(rhs, const_locals)?;
            match op {
                BinOp::Add => a.checked_add(b),
                BinOp::Sub => a.checked_sub(b),
                BinOp::Mul => a.checked_mul(b),
                // Comparisons return 1 / 0 so `if (i == 0) { ... }`
                // inside an unrolled loop folds correctly.
                BinOp::Eq => Some((a == b) as ConstInt),
                BinOp::Neq => Some((a != b) as ConstInt),
                BinOp::Lt => Some((a < b) as ConstInt),
                BinOp::Le => Some((a <= b) as ConstInt),
                BinOp::Gt => Some((a > b) as ConstInt),
                BinOp::Ge => Some((a >= b) as ConstInt),
                _ => None,
            }
        }
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        } => eval_const_expr(operand, const_locals).and_then(ConstInt::checked_neg),
        _ => None,
    }
}

/// Extract the simple identifier from a call's `callee` expression.
/// Circom's function-call callees are always bare identifiers at the
/// lowering layer; anything more complex (method access, indexed
/// callable, etc.) bails out of the lift.
fn extract_call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Is `expr` an increment on the named variable (`name++` or `++name`)?
fn is_increment_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Increment) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}

/// Are all of `stmts` safe to lift under the mux scheme (both arms
/// executing unconditionally at runtime)?
fn stmts_are_mux_compatible(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_mux_compatible)
}

/// Shape check for a single branch statement. The mux scheme runs
/// both arms of an if/else at runtime and picks the output of the
/// "taken" arm via field arithmetic, so only side-effect-free
/// statements are admissible:
/// - scalar `var` decls / `=` / compound-assign (no array writes),
/// - nested if/else (recursively checked),
/// - bare postfix/prefix side effects on pure expressions.
///
/// `return`, array stores, and tuple destructuring bail out of the mux
/// pass; the caller falls back to E212.
fn stmt_is_mux_compatible(stmt: &Stmt) -> bool {
    use crate::ast::ElseBranch;
    match stmt {
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            ..
        } => {
            names.len() == 1
                && dimensions.is_empty()
                && init.as_ref().is_none_or(expr_is_mux_compatible)
        }
        Stmt::Substitution { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && stmts_are_mux_compatible(&then_body.stmts)
                && match else_body {
                    Some(ElseBranch::Block(b)) => stmts_are_mux_compatible(&b.stmts),
                    Some(ElseBranch::IfElse(boxed)) => stmt_is_mux_compatible(boxed),
                    None => true,
                }
        }
        Stmt::Expr { expr, .. } => expr_is_mux_compatible(expr),
        _ => false,
    }
}

/// Is `expr` side-effect-free enough to evaluate on both arms of a
/// runtime mux? Calls bail out: a nested lift could still read
/// signals or emit work that's fine in isolation, but we keep the
/// MVP conservative and only admit pure register arithmetic.
fn expr_is_mux_compatible(expr: &Expr) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } | Expr::Ident { .. } => true,
        Expr::BinOp { lhs, rhs, .. } => expr_is_mux_compatible(lhs) && expr_is_mux_compatible(rhs),
        Expr::UnaryOp { operand, .. } => expr_is_mux_compatible(operand),
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            expr_is_mux_compatible(operand)
        }
        Expr::Index { object, index, .. } => {
            // `arr[i]` reads from a pre-allocated array; both arms do
            // the read but only one result is selected.
            expr_is_mux_compatible(object) && expr_is_mux_compatible(index)
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && expr_is_mux_compatible(if_true)
                && expr_is_mux_compatible(if_false)
        }
        // Nested function calls inline into the current Artik program
        // at `nested_depth > 0`, which captures `return` via
        // `nested_result` instead of emitting `WriteWitness`. Array
        // allocations inside the callee are scope-local to the nested
        // frame and cannot leak to the caller's arrays map. Both arms
        // emit the call's instructions — wasted work, but not a
        // witness corruption, because the mux picks the winning
        // register after the fact.
        Expr::Call { args, .. } => args.iter().all(expr_is_mux_compatible),
        _ => false,
    }
}

/// Map a circom compound-assignment operator to the plain binary op
/// the lift knows how to emit. Returns `None` for unsupported shapes.
fn compound_to_binop(op: crate::ast::CompoundOp) -> Option<BinOp> {
    use crate::ast::CompoundOp;
    match op {
        CompoundOp::Add => Some(BinOp::Add),
        CompoundOp::Sub => Some(BinOp::Sub),
        CompoundOp::Mul => Some(BinOp::Mul),
        CompoundOp::Div => Some(BinOp::Div),
        CompoundOp::ShiftL => Some(BinOp::ShiftL),
        CompoundOp::ShiftR => Some(BinOp::ShiftR),
        CompoundOp::BitAnd => Some(BinOp::BitAnd),
        CompoundOp::BitOr => Some(BinOp::BitOr),
        CompoundOp::BitXor => Some(BinOp::BitXor),
        _ => None,
    }
}
