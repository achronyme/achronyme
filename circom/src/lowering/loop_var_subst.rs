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

/// Given the slice `nodes[iter_start..iter_end]` covering one iteration's
/// emission, return the indices (relative to `iter_start`) of the
/// nodes that are NOT inside any flush range — i.e. the body-only
/// emission, the part that R1″ memoization can replay across iters.
///
/// `flush_ranges` are absolute indices into the same `nodes` Vec
/// (as produced by `LoweringContext::flush_tracker`). Ranges that
/// fall outside `[iter_start, iter_end)` are ignored — those flushes
/// belong to a different iteration.
///
/// The output indices are sorted ascending. This is a metadata
/// helper; it does not allocate node clones. Callers can map the
/// indices to owned nodes by cloning the corresponding entries.
pub fn body_only_indices(
    iter_start: usize,
    iter_end: usize,
    flush_ranges: &[(usize, usize)],
) -> Vec<usize> {
    if iter_end <= iter_start {
        return Vec::new();
    }
    let total = iter_end - iter_start;
    // Mark every absolute index in any flush range.
    let mut in_flush = vec![false; total];
    for &(start, end) in flush_ranges {
        // Clip the range to the iteration window.
        let lo = start.max(iter_start);
        let hi = end.min(iter_end);
        if lo >= hi {
            continue;
        }
        for i in lo..hi {
            in_flush[i - iter_start] = true;
        }
    }
    (0..total).filter(|i| !in_flush[*i]).collect()
}

/// Total node count in `flush_ranges` that falls inside the iteration
/// window `[iter_start, iter_end)`. Useful for shape statistics
/// without materializing the index vec.
pub fn flushed_node_count(
    iter_start: usize,
    iter_end: usize,
    flush_ranges: &[(usize, usize)],
) -> usize {
    flush_ranges
        .iter()
        .map(|&(start, end)| {
            let lo = start.max(iter_start);
            let hi = end.min(iter_end);
            hi.saturating_sub(lo)
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir_forge::types::{CircuitBinOp, CircuitCmpOp};

    fn const_(v: u64) -> CircuitExpr {
        CircuitExpr::Const(FieldConst::from_u64(v))
    }

    #[test]
    fn placeholder_format_is_unambiguous() {
        // The whole reason for the trailing `$` is to make `$LV7$`
        // and `$LV70$` non-overlapping under String::replace.
        assert_eq!(loop_var_placeholder(7), "$LV7$");
        assert_eq!(loop_var_placeholder(70), "$LV70$");
        assert!(!"$LV70$".contains(&loop_var_placeholder(7)));
        assert!(!"$LV7$".contains(&loop_var_placeholder(70)));
    }

    #[test]
    fn loop_var_in_five_positions_substitutes_to_const_42() {
        // Position 1: bare CircuitExpr::LoopVar in Let.value
        // Position 2: nested in arithmetic in another Let.value
        // Position 3: as AssertEq.lhs
        // Position 4: inside LetArray.elements
        // Position 5: inside a nested For body
        let inner_for_body = vec![CircuitNode::Let {
            name: "z".into(),
            value: CircuitExpr::LoopVar(7),
            span: None,
        }];
        let mut slice = vec![
            CircuitNode::Let {
                name: "x".into(),
                value: CircuitExpr::LoopVar(7),
                span: None,
            },
            CircuitNode::Let {
                name: "y".into(),
                value: CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(const_(10)),
                    rhs: Box::new(CircuitExpr::LoopVar(7)),
                },
                span: None,
            },
            CircuitNode::AssertEq {
                lhs: CircuitExpr::LoopVar(7),
                rhs: const_(0),
                message: None,
                span: None,
            },
            CircuitNode::LetArray {
                name: "arr".into(),
                elements: vec![const_(1), CircuitExpr::LoopVar(7), const_(2)],
                span: None,
            },
            CircuitNode::For {
                var: "j".into(),
                range: ForRange::Literal { start: 0, end: 3 },
                body: inner_for_body,
                span: None,
            },
        ];

        substitute_loop_var(&mut slice, 7, 42);

        // Position 1: Let { value: Const(42) }
        if let CircuitNode::Let { value, .. } = &slice[0] {
            assert_eq!(*value, const_(42));
        } else {
            panic!("position 1 not a Let");
        }
        // Position 2: Let { value: BinOp(Const(10), Const(42)) }
        if let CircuitNode::Let {
            value: CircuitExpr::BinOp { lhs, rhs, .. },
            ..
        } = &slice[1]
        {
            assert_eq!(**lhs, const_(10));
            assert_eq!(**rhs, const_(42));
        } else {
            panic!("position 2 not a BinOp");
        }
        // Position 3: AssertEq { lhs: Const(42) }
        if let CircuitNode::AssertEq { lhs, rhs, .. } = &slice[2] {
            assert_eq!(*lhs, const_(42));
            assert_eq!(*rhs, const_(0));
        } else {
            panic!("position 3 not an AssertEq");
        }
        // Position 4: LetArray { elements: [Const(1), Const(42), Const(2)] }
        if let CircuitNode::LetArray { elements, .. } = &slice[3] {
            assert_eq!(elements.len(), 3);
            assert_eq!(elements[0], const_(1));
            assert_eq!(elements[1], const_(42));
            assert_eq!(elements[2], const_(2));
        } else {
            panic!("position 4 not a LetArray");
        }
        // Position 5: For { body: [Let { value: Const(42) }] }
        if let CircuitNode::For { body, .. } = &slice[4] {
            if let CircuitNode::Let { value, .. } = &body[0] {
                assert_eq!(*value, const_(42));
            } else {
                panic!("position 5 inner body not a Let");
            }
        } else {
            panic!("position 5 not a For");
        }
    }

    #[test]
    fn slice_without_placeholder_is_unchanged() {
        // Negative test: nothing references the loop var. The
        // substitution pass must be a no-op (modulo the redundant
        // walk) and produce structurally identical output.
        let original = vec![
            CircuitNode::Let {
                name: "x".into(),
                value: const_(99),
                span: None,
            },
            CircuitNode::AssertEq {
                lhs: CircuitExpr::Var("x".into()),
                rhs: const_(99),
                message: None,
                span: None,
            },
            CircuitNode::If {
                cond: CircuitExpr::Comparison {
                    op: CircuitCmpOp::Lt,
                    lhs: Box::new(CircuitExpr::Var("x".into())),
                    rhs: Box::new(const_(100)),
                },
                then_body: vec![CircuitNode::Expr {
                    expr: CircuitExpr::Var("x".into()),
                    span: None,
                }],
                else_body: vec![],
                span: None,
            },
        ];
        let mut slice = original.clone();
        substitute_loop_var(&mut slice, 7, 42);
        assert_eq!(slice, original);
    }

    #[test]
    fn different_token_is_left_untouched() {
        // An outer-loop placeholder (token 1) must survive when the
        // inner-loop substitution runs (token 0). Tests the equality
        // guard in the LoopVar arm.
        let mut slice = vec![CircuitNode::Let {
            name: "outer".into(),
            value: CircuitExpr::LoopVar(1),
            span: None,
        }];
        substitute_loop_var(&mut slice, 0, 99);
        if let CircuitNode::Let { value, .. } = &slice[0] {
            assert_eq!(*value, CircuitExpr::LoopVar(1));
        } else {
            panic!("outer placeholder mutated");
        }
    }

    #[test]
    fn placeholder_in_name_is_substituted() {
        // Names like `t1_$LV7$` (mangled at iter-0 capture) must
        // become `t1_42` after substitution.
        let mut slice = vec![
            CircuitNode::Let {
                name: "t1_$LV7$".into(),
                value: CircuitExpr::Var("t0_$LV7$".into()),
                span: None,
            },
            CircuitNode::LetIndexed {
                array: "$LV7$_arr".into(),
                index: CircuitExpr::LoopVar(7),
                value: const_(1),
                span: None,
            },
        ];
        substitute_loop_var(&mut slice, 7, 42);
        if let CircuitNode::Let { name, value, .. } = &slice[0] {
            assert_eq!(name, "t1_42");
            assert_eq!(*value, CircuitExpr::Var("t0_42".into()));
        } else {
            panic!("not a Let");
        }
        if let CircuitNode::LetIndexed { array, index, .. } = &slice[1] {
            assert_eq!(array, "42_arr");
            assert_eq!(*index, const_(42));
        } else {
            panic!("not a LetIndexed");
        }
    }

    #[test]
    fn token_7_does_not_corrupt_token_70_placeholder() {
        // The trailing `$` makes $LV7$ ≠ a substring of $LV70$.
        // Without it, replacing token 7 would mangle $LV70$ into
        // `420$`, corrupting the outer-loop placeholder.
        let mut slice = vec![CircuitNode::Let {
            name: "shared_$LV7$_$LV70$".into(),
            value: const_(0),
            span: None,
        }];
        substitute_loop_var(&mut slice, 7, 42);
        if let CircuitNode::Let { name, .. } = &slice[0] {
            // `$LV7$` becomes `42`; `$LV70$` is preserved verbatim.
            assert_eq!(name, "shared_42_$LV70$");
        } else {
            panic!("not a Let");
        }
    }

    #[test]
    fn substitutes_inside_for_range_with_expr() {
        // ForRange::WithExpr's bound expression may reference the
        // outer loop variable: `for j in 0..(LoopVar(7) + 1)`.
        let mut slice = vec![CircuitNode::For {
            var: "j".into(),
            range: ForRange::WithExpr {
                start: 0,
                end_expr: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::LoopVar(7)),
                    rhs: Box::new(const_(1)),
                }),
            },
            body: vec![],
            span: None,
        }];
        substitute_loop_var(&mut slice, 7, 5);
        if let CircuitNode::For {
            range: ForRange::WithExpr { end_expr, .. },
            ..
        } = &slice[0]
        {
            if let CircuitExpr::BinOp { lhs, rhs, .. } = end_expr.as_ref() {
                assert_eq!(**lhs, const_(5));
                assert_eq!(**rhs, const_(1));
            } else {
                panic!("end_expr not a BinOp");
            }
        } else {
            panic!("not a For with WithExpr range");
        }
    }

    #[test]
    fn body_only_indices_no_flush_keeps_everything() {
        // No flush ranges → every index in [0, total) is body-only.
        let indices = body_only_indices(10, 15, &[]);
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn body_only_indices_drops_flush_ranges_in_window() {
        // Iteration window [10, 20). Flush emitted at [12, 15).
        // Body-only relative indices: 0, 1, 5, 6, 7, 8, 9
        // (i.e. absolute 10, 11, 15, 16, 17, 18, 19).
        let indices = body_only_indices(10, 20, &[(12, 15)]);
        assert_eq!(indices, vec![0, 1, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn body_only_indices_handles_multiple_flushes() {
        // Two flushes interleaved in the window.
        // Window [0, 10). Flushes [2, 4) and [7, 9).
        // Body-only relative: 0, 1, 4, 5, 6, 9.
        let indices = body_only_indices(0, 10, &[(2, 4), (7, 9)]);
        assert_eq!(indices, vec![0, 1, 4, 5, 6, 9]);
    }

    #[test]
    fn body_only_indices_clips_partial_overlap() {
        // Flush range [8, 13) partially overlaps window [10, 15) —
        // only [10, 13) is in-window. Body-only: 3, 4 (abs 13, 14).
        let indices = body_only_indices(10, 15, &[(8, 13)]);
        assert_eq!(indices, vec![3, 4]);
    }

    #[test]
    fn body_only_indices_ignores_out_of_window_ranges() {
        // Flush range [50, 60) is outside window [10, 20) — ignored.
        let indices = body_only_indices(10, 20, &[(50, 60)]);
        assert_eq!(indices, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn body_only_indices_empty_window_is_empty() {
        assert!(body_only_indices(5, 5, &[(0, 100)]).is_empty());
        assert!(body_only_indices(10, 5, &[]).is_empty());
    }

    #[test]
    fn flushed_node_count_sums_in_window_clipped() {
        // Window [10, 20). Flushes [12, 15) (3 in window) and
        // [18, 25) (only [18, 20) in window = 2). Total = 5.
        assert_eq!(flushed_node_count(10, 20, &[(12, 15), (18, 25)]), 5);
        // Out-of-window flush contributes 0.
        assert_eq!(flushed_node_count(10, 20, &[(50, 100)]), 0);
        // Empty window contributes 0.
        assert_eq!(flushed_node_count(20, 20, &[(0, 100)]), 0);
    }

    // ── R1″ Phase 6 / Option D — proof of concept ────────────────────
    //
    // Validates the architectural thesis that drives Option D: a
    // `LetIndexed { index: LoopVar(t) }` body, after `substitute_loop_var`
    // rewrites the placeholder to `Const(N)`, instantiates byte-identical
    // to a hand-unrolled body that uses `Const(N)` directly. If this
    // holds, the Phase 6 lowering integration can stop folding the loop
    // variable to a flat name and instead lean on instantiate's existing
    // `eval_const_expr` fast-path for `ArrayIndex` / `LetIndexed`.

    use std::collections::{HashMap, HashSet};

    use ir_core::{Instruction, IrType};
    use ir_forge::types::{CaptureArrayDef, ProveIR, ProveInputDecl};
    use memory::{Bn254Fr, FieldElement};

    /// Build a ProveIR with the given body and a single witness scalar
    /// `x` plus a public output array `out[4]`. Used by both the
    /// hand-unrolled and the substituted-from-placeholder bodies in the
    /// PoC, so that any IR delta isolates to the substitution mechanic.
    fn poc_prove_ir(body: Vec<CircuitNode>) -> ProveIR {
        ProveIR {
            name: Some("poc".into()),
            public_inputs: vec![ProveInputDecl {
                name: "out".into(),
                array_size: Some(ir_forge::types::ArraySize::Literal(4)),
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![ProveInputDecl {
                name: "x".into(),
                array_size: None,
                ir_type: IrType::Field,
            }],
            captures: vec![],
            body,
            capture_arrays: Vec::<CaptureArrayDef>::new(),
        }
    }

    /// Body shape A: hand-unrolled `out[i] <== x + i` for i in 0..4
    /// with concrete `Const` indices. Mirrors what circom's legacy
    /// loop unroll emits today.
    fn body_hand_unrolled() -> Vec<CircuitNode> {
        (0..4)
            .map(|i| CircuitNode::LetIndexed {
                array: "out".into(),
                index: CircuitExpr::Const(FieldConst::from_u64(i)),
                value: CircuitExpr::BinOp {
                    op: ir_forge::types::CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::Input("x".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(i))),
                },
                span: None,
            })
            .collect()
    }

    /// Body shape B: a one-iteration template `out[i] <== x + i` using
    /// `LoopVar(0)` for the loop var, then cloned + substituted for
    /// each iteration via `substitute_loop_var`. Post-substitute the
    /// body is structurally identical to `body_hand_unrolled`.
    fn body_loop_var_then_substituted() -> Vec<CircuitNode> {
        let template = CircuitNode::LetIndexed {
            array: "out".into(),
            index: CircuitExpr::LoopVar(0),
            value: CircuitExpr::BinOp {
                op: ir_forge::types::CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Input("x".into())),
                rhs: Box::new(CircuitExpr::LoopVar(0)),
            },
            span: None,
        };
        let mut body = Vec::with_capacity(4);
        for i in 0..4u64 {
            let mut node = template.clone();
            substitute_loop_var(std::slice::from_mut(&mut node), 0, i);
            body.push(node);
        }
        body
    }

    /// Categorise an instruction by its discriminant so the two IR
    /// streams can be compared by shape (kind sequence) without
    /// requiring SsaVar equality, which is allocator-driven and may
    /// differ across runs without indicating a real semantic delta.
    fn inst_kind(inst: &Instruction<Bn254Fr>) -> &'static str {
        match inst {
            Instruction::Const { .. } => "Const",
            Instruction::Input { .. } => "Input",
            Instruction::Add { .. } => "Add",
            Instruction::Sub { .. } => "Sub",
            Instruction::Mul { .. } => "Mul",
            Instruction::Neg { .. } => "Neg",
            Instruction::AssertEq { .. } => "AssertEq",
            _ => "Other",
        }
    }

    #[test]
    fn poc_loopvar_substitute_then_instantiate_matches_hand_unroll() {
        // The architectural claim under test: instantiate's existing
        // `ArrayIndex` / `LetIndexed` fast-path collapses
        // `LoopVar(t) → Const(N)` substitutions to the same SSA shape
        // a hand-unrolled body produces. If this passes, the Phase 6
        // lowering integration is unblocked: emit `LoopVar`, substitute
        // per iter, hand to instantiate. No string-mangling needed in
        // the lowering for the dominant signal-array case.
        let outputs: HashSet<String> = std::iter::once("out".to_string()).collect();
        let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();

        let ir_a = poc_prove_ir(body_hand_unrolled())
            .instantiate_with_outputs::<Bn254Fr>(&captures, &outputs)
            .expect("hand-unrolled ProveIR should instantiate");
        let ir_b = poc_prove_ir(body_loop_var_then_substituted())
            .instantiate_with_outputs::<Bn254Fr>(&captures, &outputs)
            .expect("substituted ProveIR should instantiate");

        // Same instruction count proves no extra wires/constraints
        // leak from the substitution path.
        assert_eq!(
            ir_a.instructions.len(),
            ir_b.instructions.len(),
            "instruction count diverged: hand-unrolled={}, substituted={}",
            ir_a.instructions.len(),
            ir_b.instructions.len(),
        );

        // Same kind sequence proves the fold path produced the same
        // operation order. SsaVar identities differ run-to-run so we
        // compare discriminants, not the full struct.
        let kinds_a: Vec<&str> = ir_a.instructions.iter().map(inst_kind).collect();
        let kinds_b: Vec<&str> = ir_b.instructions.iter().map(inst_kind).collect();
        assert_eq!(kinds_a, kinds_b, "instruction kind sequence diverged");

        // Sanity floor: the body must have actually emitted Add +
        // AssertEq instructions. Without this the shape-equality
        // above could be vacuously true on two empty streams (which
        // would happen if both ProveIRs were silently rejected at
        // scaffold time).
        //
        // Note: only 3 Adds, not 4 — instantiate's BinOp fold
        // collapses `Add(Input(x), Const(0))` to just `Input(x)` for
        // the i=0 iteration (additive identity). This identity fold
        // applies to both ProveIRs uniformly, which is precisely why
        // the kind-sequence equality above holds.
        let adds = ir_a
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Add { .. }))
            .count();
        let asserts = ir_a
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert_eq!(
            adds, 3,
            "expected 3 Add instructions (i=1,2,3 — i=0 folds via additive identity), got {adds}",
        );
        assert_eq!(
            asserts, 4,
            "expected 4 AssertEq instructions (one per output element), got {asserts}",
        );
    }
}
