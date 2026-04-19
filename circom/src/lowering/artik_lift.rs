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
//!   `UnaryOp::Neg`.
//!
//! Anything else (arrays, `if/else`, nested calls, non-constant loop
//! bounds, tuple destructuring) returns `None` silently and the
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

use diagnostics::Span;
use witness::{ElemT, FieldFamily, IntW, ProgramBuilder, Reg};

use crate::ast::{BinOp, Expr, PostfixOp, Stmt, UnaryOp};
use crate::lowering::context::LoweringContext;

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
    params: &[String],
    body: &[Stmt],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<LiftedWitnessCall> {
    let mut state = LiftState::new(params);

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
    let program_bytes = witness::bytecode::encode(&program);

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

struct LiftState {
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
}

impl LiftState {
    fn new(params: &[String]) -> Self {
        let mut builder = ProgramBuilder::new(FieldFamily::BnLike256);
        let mut locals = HashMap::new();
        for name in params {
            let sig = builder.alloc_signal();
            let reg = builder.read_signal(sig);
            locals.insert(name.clone(), reg);
        }
        Self {
            builder,
            locals,
            const_locals: HashMap::new(),
            arrays: HashMap::new(),
            halted: false,
            return_shape: ReturnShape::Scalar,
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
                if !dimensions.is_empty() {
                    if init.is_some() || dimensions.len() != 1 {
                        return None;
                    }
                    let size = eval_const_expr(&dimensions[0], &self.const_locals)?;
                    if !(0..=i64::from(u32::MAX)).contains(&size) {
                        return None;
                    }
                    let len = size as u32;
                    let handle = self.builder.alloc_array(len, ElemT::Field);
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
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                let binop = compound_to_binop(*op)?;
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
                // Array-return: `return <local_array>;` — expose each
                // element as its own witness slot so the caller can
                // re-bundle them into a `CircuitNode::LetArray`.
                if let Expr::Ident { name, .. } = value {
                    if let Some(&(arr_reg, len)) = self.arrays.get(name) {
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
                let slot = self.builder.alloc_witness_slot();
                let r = self.lift_expr(value)?;
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

    /// Lift an `if / else` whose condition folds at compile time.
    /// Runtime conditions return `None` — Artik's executor supports
    /// `JumpIf` but the lift pass does not yet synthesize the label
    /// scaffolding a runtime branch would need, so we fall back to
    /// E212 for those. Nested `else if` chains traverse through
    /// `ElseBranch::IfElse`.
    fn lift_if_else(
        &mut self,
        condition: &Expr,
        then_body: &crate::ast::Block,
        else_body: Option<&crate::ast::ElseBranch>,
    ) -> Option<()> {
        use crate::ast::ElseBranch;
        let cond = eval_const_expr(condition, &self.const_locals)?;
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
            Expr::Index { object, index, .. } => {
                // `arr[i]` where `arr` is a declared array and `i`
                // folds to a compile-time index. Emit PushConst →
                // IntFromField for the index register, then LoadArr.
                let Expr::Ident { name, .. } = object.as_ref() else {
                    return None;
                };
                let (arr_reg, len) = self.arrays.get(name).copied()?;
                let idx = eval_const_expr(index, &self.const_locals)?;
                if !(0..i64::from(len)).contains(&idx) {
                    return None;
                }
                let idx_reg = self.push_int_const(idx as u64)?;
                Some(self.builder.load_arr(arr_reg, idx_reg))
            }
            _ => None,
        }
    }

    fn lookup_ident(&mut self, name: &str) -> Option<Reg> {
        if let Some(v) = self.const_locals.get(name).copied() {
            return self.push_const_int(v);
        }
        self.locals.get(name).copied()
    }

    fn apply_field_binop(&mut self, op: BinOp, a: Reg, b: Reg) -> Option<Reg> {
        match op {
            BinOp::Add => Some(self.builder.fadd(a, b)),
            BinOp::Sub => Some(self.builder.fsub(a, b)),
            BinOp::Mul => Some(self.builder.fmul(a, b)),
            BinOp::Div => Some(self.builder.fdiv(a, b)),
            _ => None,
        }
    }

    fn push_const_int(&mut self, v: ConstInt) -> Option<Reg> {
        // Negative values need sign-correct encoding. `FieldFromInt I64`
        // is what we'd use at the executor level, but we don't have
        // int registers on this path — constants enter the register
        // file via `PushConst` (field). Encode a negative value as
        // `p - |v|` at lift time by passing through `from_i64` on the
        // wire side: we serialize the *unsigned* representation of the
        // constant (`(-v) as u64`) and flip sign with `0 - x` via an
        // FSub against a zero const. For positive values, the normal
        // LE encoding is correct.
        if v < 0 {
            let positive = self.push_const_unsigned(v.unsigned_abs() as u128)?;
            let zero = self.push_const_unsigned(0)?;
            return Some(self.builder.fsub(zero, positive));
        }
        self.push_const_unsigned(v as u128)
    }

    fn push_const_unsigned(&mut self, v: u128) -> Option<Reg> {
        let mut bytes: Vec<u8> = v.to_le_bytes().to_vec();
        while bytes.last() == Some(&0) && bytes.len() > 1 {
            bytes.pop();
        }
        let cid = self.builder.intern_const(bytes);
        Some(self.builder.push_const(cid))
    }

    fn push_const_dec(&mut self, text: &str) -> Option<Reg> {
        let v: u128 = text.parse().ok()?;
        self.push_const_unsigned(v)
    }

    fn push_const_hex(&mut self, text: &str) -> Option<Reg> {
        let v = u128::from_str_radix(text, 16).ok()?;
        self.push_const_unsigned(v)
    }

    /// Materialize a compile-time integer as a u32 int register for
    /// use as an array index. Emits two instructions (PushConst into
    /// a field register, then IntFromField U32 into the int register
    /// the executor's LoadArr / StoreArr expect).
    fn push_int_const(&mut self, v: u64) -> Option<Reg> {
        let field_reg = self.push_const_unsigned(v as u128)?;
        Some(self.builder.int_from_field(IntW::U32, field_reg))
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

/// Map a circom compound-assignment operator to the plain binary op
/// the lift knows how to emit. Returns `None` for unsupported shapes.
fn compound_to_binop(op: crate::ast::CompoundOp) -> Option<BinOp> {
    use crate::ast::CompoundOp;
    match op {
        CompoundOp::Add => Some(BinOp::Add),
        CompoundOp::Sub => Some(BinOp::Sub),
        CompoundOp::Mul => Some(BinOp::Mul),
        CompoundOp::Div => Some(BinOp::Div),
        _ => None,
    }
}
