//! R1″ for-loop body memoization: substitute the `LoopVar` placeholder.
//!
//! When `lower_for_loop` captures iter 0 of a memoizable for-loop body,
//! every reference to the loop variable's *value* becomes
//! `CircuitExpr::LoopVar(token)`, and every name that mangled in the
//! loop variable embeds `loop_var_placeholder(token)` as a substring.
//! The captured slice is then cloned for each iter `N` and rewritten
//! by `substitute_loop_var(&mut slice, token, N)`:
//!
//! - `CircuitExpr::LoopVar(token)` leaves → `CircuitExpr::Const(N)`
//! - Name strings containing `$LV{token}$` → string with that
//!   substring replaced by `N`'s decimal form
//!
//! Leaves with a *different* token are left untouched so an outer-loop
//! placeholder can survive a nested-loop substitution pass.
//!
//! Phase 2 of the R1″ pipeline (visitor only). The lowering integration
//! that actually emits `LoopVar` and the placeholder lives in Phase 3.

use ir_forge::types::{ArraySize, CircuitExpr, CircuitNode, FieldConst, ForRange};

/// Render the placeholder string used in *names* during iter-0 capture
/// (e.g. `t1_$LV7$` for token 7). Format `$LV{token}$` was chosen
/// because:
///
/// - The leading `$` is invalid in every identifier domain we target
///   (Rust fields, circom signal names, ProveIR captures), so the
///   sigil cannot collide with a real symbol.
/// - The trailing `$` lets `String::replace` distinguish `$LV7$` from
///   `$LV70$`. Without it, a token-7 substitution would corrupt the
///   prefix of token 70's placeholder; with it, the substring `$LV7$`
///   is not contained in `$LV70$` and the replace is safe under
///   nested-loop substitution.
pub fn loop_var_placeholder(token: u32) -> String {
    format!("$LV{token}$")
}

/// Walk `slice` and substitute every occurrence of the loop-var
/// placeholder (token) for the iteration value. Mutates in place;
/// callers MUST clone the captured iter-0 slice first because each
/// memoized iteration needs its own substituted copy.
///
/// Specifically:
/// - `CircuitExpr::LoopVar(token)` → `CircuitExpr::Const(FieldConst::from_u64(value))`
/// - Strings containing `loop_var_placeholder(token)` → strings with
///   that substring replaced by `value`'s decimal form
///
/// Leaves any `LoopVar` with a *different* token untouched (an outer
/// or sibling loop's placeholder). The match on `CircuitExpr` and
/// `CircuitNode` is exhaustive with no wildcard arm so any future
/// variant forces a compile-time review of substitution semantics.
///
/// # Caveat — opaque payloads
///
/// `CircuitNode::WitnessCall::program_bytes` is Artik bytecode and is
/// NOT walked. If a memoized for-loop body lifts a function whose
/// behavior depends on the loop variable, those bytecode payloads
/// retain iter-0 semantics across all memoized iterations and produce
/// a wrong witness. The Phase 3 lowering integration is responsible
/// for refusing to memoize any loop that emits an iter-dependent
/// `WitnessCall`. SHA-256's round body emits no `WitnessCall`, which
/// is why R1″ is safe for the target benchmark.
pub fn substitute_loop_var(slice: &mut [CircuitNode], token: u32, value: u64) {
    let placeholder = loop_var_placeholder(token);
    let value_str = value.to_string();
    for node in slice {
        subst_node(node, token, value, &placeholder, &value_str);
    }
}

fn subst_node(node: &mut CircuitNode, t: u32, v: u64, ph: &str, vs: &str) {
    match node {
        CircuitNode::Let { name, value, .. } => {
            subst_name(name, ph, vs);
            subst_expr(value, t, v, ph, vs);
        }
        CircuitNode::LetArray { name, elements, .. } => {
            subst_name(name, ph, vs);
            for e in elements.iter_mut() {
                subst_expr(e, t, v, ph, vs);
            }
        }
        CircuitNode::AssertEq {
            lhs,
            rhs,
            message: _,
            ..
        } => {
            subst_expr(lhs, t, v, ph, vs);
            subst_expr(rhs, t, v, ph, vs);
        }
        CircuitNode::Assert {
            expr, message: _, ..
        } => {
            subst_expr(expr, t, v, ph, vs);
        }
        CircuitNode::For {
            var, range, body, ..
        } => {
            subst_name(var, ph, vs);
            subst_range(range, t, v, ph, vs);
            for n in body.iter_mut() {
                subst_node(n, t, v, ph, vs);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            subst_expr(cond, t, v, ph, vs);
            for n in then_body.iter_mut() {
                subst_node(n, t, v, ph, vs);
            }
            for n in else_body.iter_mut() {
                subst_node(n, t, v, ph, vs);
            }
        }
        CircuitNode::Expr { expr, .. } => {
            subst_expr(expr, t, v, ph, vs);
        }
        CircuitNode::Decompose {
            name,
            value,
            num_bits: _,
            ..
        } => {
            subst_name(name, ph, vs);
            subst_expr(value, t, v, ph, vs);
        }
        CircuitNode::WitnessHint { name, hint, .. } => {
            subst_name(name, ph, vs);
            subst_expr(hint, t, v, ph, vs);
        }
        CircuitNode::WitnessArrayDecl { name, size, .. } => {
            subst_name(name, ph, vs);
            subst_array_size(size, ph, vs);
        }
        CircuitNode::LetIndexed {
            array,
            index,
            value,
            ..
        } => {
            subst_name(array, ph, vs);
            subst_expr(index, t, v, ph, vs);
            subst_expr(value, t, v, ph, vs);
        }
        CircuitNode::WitnessHintIndexed {
            array, index, hint, ..
        } => {
            subst_name(array, ph, vs);
            subst_expr(index, t, v, ph, vs);
            subst_expr(hint, t, v, ph, vs);
        }
        CircuitNode::WitnessCall {
            output_bindings,
            input_signals,
            program_bytes: _,
            ..
        } => {
            for ob in output_bindings.iter_mut() {
                subst_name(ob, ph, vs);
            }
            for is in input_signals.iter_mut() {
                subst_expr(is, t, v, ph, vs);
            }
            // program_bytes intentionally untouched — see the
            // module-level caveat about Artik bytecode opacity.
        }
    }
}

fn subst_expr(expr: &mut CircuitExpr, t: u32, v: u64, ph: &str, vs: &str) {
    match expr {
        // The placeholder leaf — the substitution's payload.
        CircuitExpr::LoopVar(this_token) => {
            if *this_token == t {
                *expr = CircuitExpr::Const(FieldConst::from_u64(v));
            }
        }
        // Other leaves — only names need substitution.
        CircuitExpr::Const(_) => {}
        CircuitExpr::Input(name)
        | CircuitExpr::Capture(name)
        | CircuitExpr::Var(name)
        | CircuitExpr::ArrayLen(name) => subst_name(name, ph, vs),

        // Recursive arithmetic / boolean.
        CircuitExpr::BinOp { op: _, lhs, rhs }
        | CircuitExpr::Comparison { op: _, lhs, rhs }
        | CircuitExpr::BoolOp { op: _, lhs, rhs } => {
            subst_expr(lhs, t, v, ph, vs);
            subst_expr(rhs, t, v, ph, vs);
        }
        CircuitExpr::UnaryOp { op: _, operand } => {
            subst_expr(operand, t, v, ph, vs);
        }
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            subst_expr(cond, t, v, ph, vs);
            subst_expr(if_true, t, v, ph, vs);
            subst_expr(if_false, t, v, ph, vs);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            subst_expr(left, t, v, ph, vs);
            subst_expr(right, t, v, ph, vs);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args.iter_mut() {
                subst_expr(a, t, v, ph, vs);
            }
        }
        CircuitExpr::RangeCheck { value, bits: _ } => {
            subst_expr(value, t, v, ph, vs);
        }
        CircuitExpr::MerkleVerify {
            root,
            leaf,
            path,
            indices,
        } => {
            subst_expr(root, t, v, ph, vs);
            subst_expr(leaf, t, v, ph, vs);
            subst_name(path, ph, vs);
            subst_name(indices, ph, vs);
        }
        CircuitExpr::ArrayIndex { array, index } => {
            subst_name(array, ph, vs);
            subst_expr(index, t, v, ph, vs);
        }
        CircuitExpr::Pow { base, exp: _ } => {
            subst_expr(base, t, v, ph, vs);
        }
        CircuitExpr::IntDiv {
            lhs,
            rhs,
            max_bits: _,
        }
        | CircuitExpr::IntMod {
            lhs,
            rhs,
            max_bits: _,
        } => {
            subst_expr(lhs, t, v, ph, vs);
            subst_expr(rhs, t, v, ph, vs);
        }
        CircuitExpr::BitAnd {
            lhs,
            rhs,
            num_bits: _,
        }
        | CircuitExpr::BitOr {
            lhs,
            rhs,
            num_bits: _,
        }
        | CircuitExpr::BitXor {
            lhs,
            rhs,
            num_bits: _,
        } => {
            subst_expr(lhs, t, v, ph, vs);
            subst_expr(rhs, t, v, ph, vs);
        }
        CircuitExpr::BitNot {
            operand,
            num_bits: _,
        } => {
            subst_expr(operand, t, v, ph, vs);
        }
        CircuitExpr::ShiftR {
            operand,
            shift,
            num_bits: _,
        }
        | CircuitExpr::ShiftL {
            operand,
            shift,
            num_bits: _,
        } => {
            subst_expr(operand, t, v, ph, vs);
            subst_expr(shift, t, v, ph, vs);
        }
    }
}

fn subst_range(range: &mut ForRange, t: u32, v: u64, ph: &str, vs: &str) {
    match range {
        ForRange::Literal { .. } => {}
        ForRange::WithCapture {
            start: _,
            end_capture,
        } => subst_name(end_capture, ph, vs),
        ForRange::WithExpr { start: _, end_expr } => subst_expr(end_expr, t, v, ph, vs),
        ForRange::Array(name) => subst_name(name, ph, vs),
    }
}

fn subst_array_size(size: &mut ArraySize, ph: &str, vs: &str) {
    match size {
        ArraySize::Literal(_) => {}
        ArraySize::Capture(name) => subst_name(name, ph, vs),
    }
}

fn subst_name(name: &mut String, ph: &str, vs: &str) {
    if name.contains(ph) {
        *name = name.replace(ph, vs);
    }
}
