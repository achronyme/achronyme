//! fold-known-array-index pass: post-substitute known-array index fold.
//!
//! Sibling pass to [`crate::lowering::loop_var_subst`]. Where
//! `substitute_loop_var` is strictly env-free, this pass is
//! **env-coupled**: it consults a snapshot of
//! `LoweringEnv::known_array_values` to resolve `ArrayIndex` reads
//! whose `array` is a compile-time `EvalValue::Array` (e.g. Poseidon's
//! `C[i+r]`, BabyJubjub's coefficient tables, etc.) once their `index`
//! has folded to a single `Const`.
//!
//! ## Why this pass exists
//!
//! Memoizing a loop body whose strategy is `LoopLowering::KnownArrayRefs`
//! requires emitting `CircuitExpr::ArrayIndex { array, index: <symbolic
//! with LoopVar(token)> }` during iter-0 capture so that
//! `substitute_loop_var` can rewrite the `LoopVar(token)` leaf per
//! replay iteration. Without this fold the substituted node would carry
//! `ArrayIndex { array: "C", index: BinOp(Const(N), Const(r)) }` into
//! instantiate, which would then fail because `C` has no instantiate-env
//! binding (it lives only in lowering's `known_array_values`). The
//! legacy unroll path collapses `C[i+r]` to `Const(fc)` directly via
//! `lower_index` Case 0; this pass mirrors that collapse late, AFTER
//! `substitute_loop_var` makes the index foldable.
//!
//! ## Contract
//!
//! - **1-D and uniformly-dimensioned 2-D shapes.** The pass folds
//!   `ArrayIndex { array, index }` nodes whose `index` constant-folds to
//!   a single `FieldConst` representing a row-major linearised index. For
//!   1-D `EvalValue::Array([scalar0, scalar1, ...])` the linearised
//!   index is just the array position. For 2-D `EvalValue::Array([
//!   Array([s00, ..]), Array([s10, ..]), ...])` with uniform inner
//!   length, the linearised index `linear` decomposes to `arr[linear /
//!   inner_len][linear % inner_len]`, mirroring `lower_multi_index`'s
//!   row-major linearisation via row strides. Non-uniform 2-D shapes,
//!   3-D+ shapes, and missing-key / non-foldable indices are passthrough.
//! - **Why 2-D matters.** memoization admit/soundness check admits Mix's outer-i
//!   body for memoization, which reads `M[j][i]` with `M` a uniform t×t
//!   matrix in `known_array_values` (no `env.strides` registered, but
//!   `lower_multi_index` derives strides from the kav structure on the
//!   spot). After substitute, the residual `ArrayIndex { array: "M",
//!   index: Const(j*t + i) }` reaches this pass; the 2-D linearisation
//!   below collapses it to the scalar leaf.
//! - **Pass-through on missing keys / non-foldable indices.** A node
//!   whose `array` isn't in `kav`, or whose `index` doesn't constant-
//!   fold, is left structurally unchanged. Defence-in-depth phantom-
//!   guards (E213) catch the symbolic-residual case at the lowering
//!   site upstream.
//! - **Exhaustive match style.** Walker mirrors `loop_var_subst.rs`'s
//!   exhaustive-no-wildcard match so any future `CircuitNode` /
//!   `CircuitExpr` variant forces a compile-time review of fold
//!   semantics.
//!
//! ## Invocation
//!
//! Called from `memoize_loop` (`statements/loops.rs`) once per
//! captured iteration body — both the in-place iter-`start`
//! substitution and each per-iter replay — immediately after
//! `substitute_loop_var`.
//!
//! ## Commit history
//!
//! - `3b4a3707` Edits 1+2 — module + walker + unit tests.
//! - `41538cc0` Edits 3+4+5 — E213 phantom-`ArrayIndex` guards
//!   relaxed at single-dim (`expressions/mod.rs`) and multi-dim
//!   (`expressions/indexing.rs`) lowering sites so the symbolic
//!   `ArrayIndex` flows through to this fold pass instead of erroring.
//! - `f4488f7e` Edit 6 — `substitute_then_fold_matches_hand_unrolled_iter_n`
//!   composition contract pin in the unit-test module below.
//! - `2bd57034` Edits 7+8 — `is_memoizable` strategy gate drop
//!   accepts `KnownArrayRefs` alongside `IndexedAssignmentLoop`, plus
//!   the `memoize_loop` wire-up that calls this fold pass after both
//!   `substitute_loop_var` invocations.

use std::collections::HashMap;

use ir_forge::types::{ArraySize, CircuitExpr, CircuitNode, FieldConst, ForRange};

use super::const_fold::try_fold_const;
use super::expressions::indexing::eval_value_to_field_const;
use super::utils::EvalValue;

/// Walk `slice` and rewrite every `CircuitExpr::ArrayIndex { array,
/// index }` whose `array` keys into `kav` AND whose `index` constant-
/// folds to a single `FieldConst` indexable to a scalar leaf, into the
/// resulting `CircuitExpr::Const(fc)`.
///
/// `kav` must be the snapshot of `LoweringEnv::known_array_values`
/// taken at memoize-loop entry (see `memoize_loop` in
/// `statements/loops.rs`). Late-bound entries created during body
/// lowering are rare today but a dedicated risk noted in the Option II
/// plan §7; verify per call site.
pub fn fold_known_array_indices(slice: &mut [CircuitNode], kav: &HashMap<String, EvalValue>) {
    for node in slice {
        fold_node(node, kav);
    }
}

fn fold_node(node: &mut CircuitNode, kav: &HashMap<String, EvalValue>) {
    match node {
        CircuitNode::Let { name: _, value, .. } => {
            fold_expr(value, kav);
        }
        CircuitNode::LetArray {
            name: _, elements, ..
        } => {
            for e in elements.iter_mut() {
                fold_expr(e, kav);
            }
        }
        CircuitNode::AssertEq {
            lhs,
            rhs,
            message: _,
            ..
        } => {
            fold_expr(lhs, kav);
            fold_expr(rhs, kav);
        }
        CircuitNode::Assert {
            expr, message: _, ..
        } => {
            fold_expr(expr, kav);
        }
        CircuitNode::For {
            var: _,
            range,
            body,
            ..
        } => {
            fold_range(range, kav);
            for n in body.iter_mut() {
                fold_node(n, kav);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            fold_expr(cond, kav);
            for n in then_body.iter_mut() {
                fold_node(n, kav);
            }
            for n in else_body.iter_mut() {
                fold_node(n, kav);
            }
        }
        CircuitNode::Expr { expr, .. } => {
            fold_expr(expr, kav);
        }
        CircuitNode::Decompose {
            name: _,
            value,
            num_bits: _,
            ..
        } => {
            fold_expr(value, kav);
        }
        CircuitNode::WitnessHint { name: _, hint, .. } => {
            fold_expr(hint, kav);
        }
        CircuitNode::WitnessArrayDecl { name: _, size, .. } => {
            fold_array_size(size, kav);
        }
        CircuitNode::LetIndexed {
            array: _,
            index,
            value,
            ..
        } => {
            fold_expr(index, kav);
            fold_expr(value, kav);
        }
        CircuitNode::WitnessHintIndexed {
            array: _,
            index,
            hint,
            ..
        } => {
            fold_expr(index, kav);
            fold_expr(hint, kav);
        }
        CircuitNode::WitnessCall {
            output_bindings: _,
            input_signals,
            program_bytes: _,
            ..
        } => {
            for is in input_signals.iter_mut() {
                fold_expr(is, kav);
            }
            // program_bytes is opaque Artik bytecode — same caveat as
            // loop_var_subst's WitnessCall arm.
        }
    }
}

fn fold_expr(expr: &mut CircuitExpr, kav: &HashMap<String, EvalValue>) {
    match expr {
        // Leaves with no recursion needed.
        CircuitExpr::Const(_)
        | CircuitExpr::LoopVar(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Capture(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}

        // Recursive arithmetic / boolean.
        CircuitExpr::BinOp { op: _, lhs, rhs }
        | CircuitExpr::Comparison { op: _, lhs, rhs }
        | CircuitExpr::BoolOp { op: _, lhs, rhs } => {
            fold_expr(lhs, kav);
            fold_expr(rhs, kav);
        }
        CircuitExpr::UnaryOp { op: _, operand } => {
            fold_expr(operand, kav);
        }
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            fold_expr(cond, kav);
            fold_expr(if_true, kav);
            fold_expr(if_false, kav);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            fold_expr(left, kav);
            fold_expr(right, kav);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args.iter_mut() {
                fold_expr(a, kav);
            }
        }
        CircuitExpr::RangeCheck { value, bits: _ } => {
            fold_expr(value, kav);
        }
        CircuitExpr::MerkleVerify {
            root,
            leaf,
            path: _,
            indices: _,
        } => {
            fold_expr(root, kav);
            fold_expr(leaf, kav);
        }

        // The fold target. Recurse into the index first so any nested
        // ArrayIndex collapses bottom-up; then attempt the kav-resolve
        // step on the (possibly newly-folded) shape.
        CircuitExpr::ArrayIndex { array, index } => {
            fold_expr(index, kav);
            if let Some(arr_val) = kav.get(array.as_str()) {
                if let Some(idx_fc) = try_fold_const(index) {
                    if let Some(idx_u64) = idx_fc.to_u64() {
                        if let Some(fc) = lookup_kav_linear(arr_val, idx_u64 as usize) {
                            *expr = CircuitExpr::Const(fc);
                        }
                    }
                }
            }
        }

        CircuitExpr::Pow { base, exp: _ } => {
            fold_expr(base, kav);
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
            fold_expr(lhs, kav);
            fold_expr(rhs, kav);
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
            fold_expr(lhs, kav);
            fold_expr(rhs, kav);
        }
        CircuitExpr::BitNot {
            operand,
            num_bits: _,
        } => {
            fold_expr(operand, kav);
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
            fold_expr(operand, kav);
            fold_expr(shift, kav);
        }
    }
}

fn fold_range(range: &mut ForRange, kav: &HashMap<String, EvalValue>) {
    match range {
        ForRange::Literal { .. } | ForRange::WithCapture { .. } | ForRange::Array(_) => {}
        ForRange::WithExpr { start: _, end_expr } => fold_expr(end_expr, kav),
    }
}

fn fold_array_size(_size: &mut ArraySize, _kav: &HashMap<String, EvalValue>) {
    // ArraySize variants carry no expressions — Literal / Capture only.
    // Kept as an explicit no-op so future variants force review here.
}

/// Look up a row-major flattened linear index against a known-array
/// value, supporting 1-D and uniformly-dimensioned 2-D shapes.
///
/// Mirrors the linearisation [`super::expressions::indexing::lower_multi_index`]
/// produces. For a 2-D `EvalValue::Array([Array([..]), Array([..]), ...])`
/// with uniform inner length `n`, an index expression `M[j][i]` lowers to
/// `M[j*n + i]`; this helper inverts that linearisation by computing
/// `(linear / inner_len, linear % inner_len)` and indexing into the inner
/// row.
///
/// Returns `None` if the value is not an array, the linear index is out
/// of bounds, the inner row at the computed offset is not a uniform
/// matching `EvalValue::Array` of the same length as the first row
/// (defensive check against ragged shapes), or the leaf is not
/// scalar-convertible (`EvalValue::Array(_)` at the leaf level —
/// 3-D+ shapes return `None` here, deferred until a real consumer).
fn lookup_kav_linear(arr_val: &EvalValue, linear: usize) -> Option<FieldConst> {
    let outer = match arr_val {
        EvalValue::Array(elems) => elems,
        _ => return None,
    };
    let first = outer.first()?;
    if matches!(first, EvalValue::Array(_)) {
        // 2-D row-major flatten.
        let inner_len = first.len()?;
        if inner_len == 0 {
            return None;
        }
        let row = linear / inner_len;
        let col = linear % inner_len;
        let row_val = outer.get(row)?;
        // Uniformity defence: rows must be Arrays of the same length.
        // A ragged 2-D would silently mis-index, so refuse to fold.
        match row_val {
            EvalValue::Array(_) if row_val.len() == Some(inner_len) => {
                eval_value_to_field_const(row_val.index(col)?)
            }
            _ => None,
        }
    } else {
        // 1-D direct lookup.
        eval_value_to_field_const(outer.get(linear)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ir_forge::types::{CircuitBinOp, FieldConst};

    use crate::lowering::utils::bigval::BigVal;

    fn const_(v: u64) -> CircuitExpr {
        CircuitExpr::Const(FieldConst::from_u64(v))
    }

    fn scalar(v: u64) -> EvalValue {
        EvalValue::Scalar(BigVal::from_u64(v))
    }

    fn array_1d(values: &[u64]) -> EvalValue {
        EvalValue::Array(values.iter().map(|&v| scalar(v)).collect())
    }

    fn kav_with(name: &str, value: EvalValue) -> HashMap<String, EvalValue> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), value);
        m
    }

    /// Single-dim Ark-shape: `out_i <== in_i + C[Add(LoopVar(0), Const(r))]`.
    /// After substitute_loop_var the index becomes
    /// `Add(Const(N), Const(r))`. The fold pass must collapse that to
    /// `Const(C[N+r])`.
    #[test]
    fn folds_ark_shape_after_substitute() {
        let kav = kav_with("C", array_1d(&[100, 200, 300, 400, 500]));
        // index = Add(Const(2), Const(1)) — represents loop var i=2
        // already substituted with r=1.
        let mut expr = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(const_(2)),
                rhs: Box::new(const_(1)),
            }),
        };
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, const_(400)); // C[2+1] = C[3] = 400
    }

    /// Bare `Const(N)` index also folds. This mirrors the post-fold
    /// shape for `C[i]` where the placeholder substituted directly to a
    /// `Const` leaf at the outermost position.
    #[test]
    fn folds_bare_const_index() {
        let kav = kav_with("C", array_1d(&[42, 43, 44]));
        let mut expr = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(const_(1)),
        };
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, const_(43));
    }

    /// Non-`Const` index after substitute (e.g. placeholder leaked
    /// through somehow) leaves the node structurally unchanged. The
    /// pass MUST NOT silently swallow shapes it can't resolve — the
    /// downstream instantiate path will surface the residual.
    #[test]
    fn passes_through_non_const_index() {
        let kav = kav_with("C", array_1d(&[100, 200, 300]));
        let original = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(CircuitExpr::Var("unresolved".to_string())),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// Index with a `LoopVar` leaf inside `BinOp` doesn't fold —
    /// `try_fold_const` returns `None` for `LoopVar(_)`. Defence: the
    /// pass MUST leave the node untouched so the residual surfaces
    /// downstream rather than baking a garbage value.
    #[test]
    fn passes_through_loopvar_residual() {
        let kav = kav_with("C", array_1d(&[100, 200, 300]));
        let original = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::LoopVar(0)),
                rhs: Box::new(const_(1)),
            }),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// `ArrayIndex { array }` whose key is absent from `kav` is left
    /// untouched. The pass must not collapse arbitrary signal-array
    /// reads — only bindings backed by a compile-time `EvalValue`.
    #[test]
    fn passes_through_missing_key() {
        let kav = HashMap::new();
        let original = CircuitExpr::ArrayIndex {
            array: "S".to_string(),
            index: Box::new(const_(0)),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// memoization admit/soundness check: 2-D `EvalValue::Array(EvalValue::
    /// Array(_))` with a uniform inner length resolves via row-major
    /// flatten. `M[j*inner_len + i]` decomposes to `M[j][i]`.
    /// Mirrors `lower_multi_index`'s linearisation for kav-derived
    /// strides (Mix's `M[j][i]` case).
    #[test]
    fn folds_uniform_2d_via_row_major_flatten() {
        let inner_a = array_1d(&[1, 2, 3]); // M[0]
        let inner_b = array_1d(&[4, 5, 6]); // M[1]
        let inner_c = array_1d(&[7, 8, 9]); // M[2]
        let m = EvalValue::Array(vec![inner_a, inner_b, inner_c]);
        let kav = kav_with("M", m);
        // M[1][2] linearised with inner_len=3 → 1*3+2 = 5
        let mut expr = CircuitExpr::ArrayIndex {
            array: "M".to_string(),
            index: Box::new(const_(5)),
        };
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, const_(6)); // M[1][2] = 6
    }

    /// memoization admit/soundness check: row-major flatten covers row-0 too —
    /// confirms the `(linear / inner_len, linear % inner_len)` decomp
    /// handles linear=0 correctly (row=0, col=0).
    #[test]
    fn folds_uniform_2d_first_element() {
        let inner_a = array_1d(&[42, 43, 44]);
        let inner_b = array_1d(&[45, 46, 47]);
        let m = EvalValue::Array(vec![inner_a, inner_b]);
        let kav = kav_with("M", m);
        let mut expr = CircuitExpr::ArrayIndex {
            array: "M".to_string(),
            index: Box::new(const_(0)),
        };
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, const_(42));
    }

    /// Ragged 2-D (rows have different inner lengths) must NOT fold —
    /// the linearisation formula assumes uniform inner length, so a
    /// ragged shape would silently mis-index. Defence: refuse to fold,
    /// pass through untouched.
    #[test]
    fn passes_through_ragged_2d() {
        let inner_a = array_1d(&[1, 2, 3]); // length 3
        let inner_b = array_1d(&[4, 5]); // length 2 — RAGGED
        let m = EvalValue::Array(vec![inner_a, inner_b]);
        let kav = kav_with("M", m);
        // linear=3 → row=1, col=0 under inner_len=3. row_val is
        // Array(len=2), uniformity check fails → passthrough.
        let original = CircuitExpr::ArrayIndex {
            array: "M".to_string(),
            index: Box::new(const_(3)),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// 3-D `EvalValue::Array(Array(Array(_)))` is not handled — the
    /// `lookup_kav_linear` helper returns None on a 3-D leaf because
    /// the 2-D row contains another Array, not a scalar. Passthrough.
    /// Documented limitation; extend if a real consumer arrives.
    #[test]
    fn passes_through_3d_array_value() {
        let leaf_a = array_1d(&[1, 2]);
        let leaf_b = array_1d(&[3, 4]);
        let row = EvalValue::Array(vec![leaf_a, leaf_b]);
        let m = EvalValue::Array(vec![row]);
        let kav = kav_with("M", m);
        let original = CircuitExpr::ArrayIndex {
            array: "M".to_string(),
            index: Box::new(const_(0)),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// Out-of-bounds index is a pass-through (the leaf is None). The
    /// fold pass MUST NOT invent a value here.
    #[test]
    fn passes_through_oob_index() {
        let kav = kav_with("C", array_1d(&[100, 200])); // len 2
        let original = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(const_(5)),
        };
        let mut expr = original.clone();
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, original);
    }

    /// Nested fold: `ArrayIndex { array: "C", index: ArrayIndex {
    /// array: "T", index: Const(0) } }` — outer index is itself a
    /// kav-foldable expression. The inner ArrayIndex collapses first
    /// (bottom-up recursion), then the outer can collapse.
    #[test]
    fn nested_array_index_folds_bottom_up() {
        let kav = {
            let mut m = HashMap::new();
            m.insert("T".to_string(), array_1d(&[3])); // T[0] = 3
            m.insert("C".to_string(), array_1d(&[10, 20, 30, 40])); // C[3] = 40
            m
        };
        let mut expr = CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(CircuitExpr::ArrayIndex {
                array: "T".to_string(),
                index: Box::new(const_(0)),
            }),
        };
        fold_expr(&mut expr, &kav);
        assert_eq!(expr, const_(40));
    }

    /// Top-level walker: `fold_known_array_indices` mutates a slice in
    /// place. Verify it walks `Let { value: ArrayIndex {...} }` shapes
    /// (the dominant Ark emission).
    #[test]
    fn slice_walker_folds_let_value_array_index() {
        let kav = kav_with("C", array_1d(&[7, 8, 9, 10, 11, 12]));
        let mut slice = vec![CircuitNode::Let {
            name: "out_2".to_string(),
            value: CircuitExpr::ArrayIndex {
                array: "C".to_string(),
                index: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(const_(2)),
                    rhs: Box::new(const_(1)),
                }),
            },
            span: None,
        }];
        fold_known_array_indices(&mut slice, &kav);
        if let CircuitNode::Let { value, .. } = &slice[0] {
            assert_eq!(*value, const_(10)); // C[2+1] = C[3] = 10
        } else {
            panic!("expected Let after fold");
        }
    }

    /// Empty `kav` is a no-op: the pass walks the slice but every
    /// `ArrayIndex` falls through the missing-key check unchanged.
    #[test]
    fn empty_kav_is_noop() {
        let kav = HashMap::new();
        let original = vec![CircuitNode::Let {
            name: "x".to_string(),
            value: CircuitExpr::ArrayIndex {
                array: "C".to_string(),
                index: Box::new(const_(0)),
            },
            span: None,
        }];
        let mut slice = original.clone();
        fold_known_array_indices(&mut slice, &kav);
        assert_eq!(slice, original);
    }

    /// Composition contract for R1″ Option II: an Ark-shape iter-0
    /// capture body — `Let { value: ArrayIndex { array: "C", index:
    /// BinOp::Add(LoopVar(0), Const(r)) } }` — when run through
    /// `substitute_loop_var(token=0, value=N)` followed by
    /// `fold_known_array_indices(kav)`, must produce a body
    /// structurally identical to the legacy hand-unrolled iter `N`
    /// emission, which is `Let { value: Const(C[N+r]) }`.
    ///
    /// This is the load-bearing invariant Option II depends on.
    /// Memoization captures iter-0 with the placeholder, then for each
    /// replay iter clones the captured body and runs substitute + fold;
    /// constraint downstream sees the same `Const` leaves a legacy
    /// unroll would have emitted via `lower_index` Case 0
    /// (`try_resolve_known_array_index`). If this composition diverges,
    /// the cross-mode constraint pin
    /// (`r1pp_followup_b_eddsaposeidon_constraint_count_byte_identical_across_modes`)
    /// would catch the divergence at e2e level — but tripping there
    /// after a refactor leaves you debugging through 31685 nodes;
    /// tripping here points the diff straight at the substitute/fold
    /// boundary.
    #[test]
    fn substitute_then_fold_matches_hand_unrolled_iter_n() {
        use crate::lowering::loop_var_subst::substitute_loop_var;

        // Ark coefficient table for t=4, r=0: synthetic values 100..104.
        let kav = kav_with("C", array_1d(&[100, 101, 102, 103, 104, 105]));

        // Iter-0 capture body shape: out_$LV0$ <== in_$LV0$ + C[i + 1]
        // (r = 1 picked deliberately so the index is an Add, not a
        // bare LoopVar — this is the Ark-with-r-offset case the
        // advisor flagged as the dominant production shape).
        let template = vec![CircuitNode::Let {
            name: "out_$LV0$".to_string(),
            value: CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("in_$LV0$".to_string())),
                rhs: Box::new(CircuitExpr::ArrayIndex {
                    array: "C".to_string(),
                    index: Box::new(CircuitExpr::BinOp {
                        op: CircuitBinOp::Add,
                        lhs: Box::new(CircuitExpr::LoopVar(0)),
                        rhs: Box::new(const_(1)),
                    }),
                }),
            },
            span: None,
        }];

        // Replay iters 0..4 via substitute + fold; collect each result.
        let mut composed: Vec<CircuitNode> = Vec::new();
        for n in 0..4u64 {
            let mut iter = template.clone();
            substitute_loop_var(&mut iter, 0, n);
            fold_known_array_indices(&mut iter, &kav);
            composed.extend(iter);
        }

        // Hand-unrolled emission: out_n <== in_n + Const(C[n+1]).
        let hand_unrolled: Vec<CircuitNode> = (0..4u64)
            .map(|n| CircuitNode::Let {
                name: format!("out_{n}"),
                value: CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::Var(format!("in_{n}"))),
                    rhs: Box::new(const_(100 + n + 1)),
                },
                span: None,
            })
            .collect();

        assert_eq!(
            composed, hand_unrolled,
            "Option II contract: substitute_loop_var + fold_known_array_indices \
             must produce structurally-identical IR to a hand-unrolled body. \
             Divergence here breaks the byte-identical-constraints invariant \
             that EdDSAPoseidon's cross-mode pin enforces at e2e level."
        );
    }
}
